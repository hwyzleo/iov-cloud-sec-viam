package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionDecision;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionReason;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.BindStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceStatus;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DecisionAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertificateVerificationAdapter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 设备接入准入裁决应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-004 / D-VIAM-005）
 * <p>
 * 迁入 TSP 准入裁决安全能力（ViamDeviceAdmissionService），直读 VIAM 安全主体、
 * VMD 绑定事实与 FW-SEC 证书状态；编排顺序固定为：UID → 绑定 → 证书吊销/身份/有效期 →
 * 安全开通态 → 裁决。任何无法获得确定 VALID/REVOKED 的 PKI 依赖结果一律 fail-closed
 * （DENY + DEPENDENCY_UNAVAILABLE），不得降级为 ALLOW，依赖故障不伪装为吊销。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceAdmissionAppService {

    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final DeviceOnboardingRepository onboardingRepository;
    private final DecisionAuditRepository decisionAuditRepository;
    private final CertificateVerificationAdapter certificateVerificationAdapter;

    /** 准入快照有效期（分钟，从配置读取） */
    private static final long SNAPSHOT_MAX_AGE_MINUTES = 10;

    private long snapshotMaxAgeSeconds() {
        return SNAPSHOT_MAX_AGE_MINUTES * 60;
    }

    /**
     * 执行准入裁决（ALLOW 仅表示认证/准入通过，不等于成功建链）。
     *
     * @param request 裁决请求
     * @param caller  调用方标识
     * @return 裁决结果（已落审计，含 admissionDecisionId）
     */
    @Transactional(rollbackFor = Exception.class)
    public DeviceAdmissionResultVo decide(DeviceAdmissionCheckVo request, String caller) {
        Instant decisionAt = request.getTs() == null ? Instant.now() : request.getTs();
        String uidDigest = ViamUtils.sha256Hex(request.getUid());
        String certSerialDigest = ViamUtils.sha256Hex(request.getCertSerial());
        String sourceIpDigest = ViamUtils.sha256Hex(request.getSourceIp());
        String decisionId = ViamUtils.newAdmissionDecisionId();

        long start = System.currentTimeMillis();
        DecisionAudit audit = evaluate(request, decisionId, decisionAt, caller, uidDigest, certSerialDigest, sourceIpDigest);
        audit.setResponseTimeMs(System.currentTimeMillis() - start);

        decisionAuditRepository.save(audit);
        log.info("VIAM准入裁决完成: decisionId={}, decision={}, reason={}, time={}ms",
                decisionId, audit.getDecision(), audit.getReason(), audit.getResponseTimeMs());

        return DeviceAdmissionResultVo.builder()
                .decision(AdmissionDecision.valOf(audit.getDecision()))
                .reason(AdmissionReason.valOf(audit.getReason()))
                .vin(audit.getVin())
                .bindStatus(BindStatus.valOf(audit.getBindStatus()))
                .certStatus(CertificateStatus.valOf(audit.getCertStatus()))
                .deviceStatus(DeviceStatus.valOf(audit.getDeviceStatus()))
                .bindVersion(audit.getBindVersion())
                .securityVersion(currentSecurityVersion(request.getUid()))
                .updatedAt(Instant.now())
                .admissionDecisionId(decisionId)
                .build();
    }

    /**
     * 会话授权时的安全状态版本（G-3）：VAGW 记录于会话/准入上下文，供乱序失效事件判定
     * （block(v10) 事件迟到时，v11 授权的新会话不受影响）。读取失败不阻断准入，以 0 兜底。
     */
    private long currentSecurityVersion(String uid) {
        try {
            String normalized = ViamUtils.normalizeUid(uid);
            if (normalized == null) {
                return 0L;
            }
            SecurityPrincipal principal = principalRepository.findByHsmUid(normalized).orElse(null);
            if (principal == null) {
                return 0L;
            }
            return onboardingRepository.findByPrincipalId(principal.getPrincipalId())
                    .map(DeviceOnboarding::getSecurityVersion)
                    .orElse(0L);
        } catch (Exception e) {
            log.warn("安全状态版本读取失败（以0兜底）: uid={}", ViamUtils.sha256Hex(uid), e);
            return 0L;
        }
    }

    private DecisionAudit evaluate(DeviceAdmissionCheckVo request, String decisionId, Instant decisionAt,
                                   String caller, String uidDigest, String certSerialDigest, String sourceIpDigest) {
        DecisionAudit audit = DecisionAudit.builder()
                .admissionDecisionId(decisionId)
                .caller(caller)
                .uidDigest(uidDigest)
                .certSerialDigest(certSerialDigest)
                .sourceIpDigest(sourceIpDigest)
                .decisionAt(decisionAt)
                .build();

        // 1. UID 必须在受信安全主体登记中存在（不得仅信客户端自报）
        String uid = ViamUtils.normalizeUid(request.getUid());
        SecurityPrincipal principal = uid == null ? null : principalRepository.findByHsmUid(uid).orElse(null);
        if (principal == null) {
            return deny(audit, AdmissionReason.UID_UNKNOWN, BindStatus.UNKNOWN, null, null, null);
        }
        if (principal.getState() == SecurityPrincipal.PrincipalState.BLOCKED) {
            return deny(audit, AdmissionReason.DEVICE_BLOCKED, BindStatus.BOUND, CertificateStatus.UNKNOWN,
                    DeviceStatus.BLOCKED, principal.getPrincipalId());
        }
        if (principal.getState() == SecurityPrincipal.PrincipalState.RETIRED) {
            return deny(audit, AdmissionReason.DEVICE_RETIRED, BindStatus.BOUND, CertificateStatus.UNKNOWN,
                    DeviceStatus.RETIRED, principal.getPrincipalId());
        }

        // 2. 资产映射必须唯一 ACTIVE（VMD 事实投影）
        List<PrincipalAssetMapping> mappings = mappingRepository.listActiveByPrincipalId(principal.getPrincipalId());
        if (mappings.isEmpty()) {
            return deny(audit, AdmissionReason.UNBOUND, BindStatus.UNBOUND, null, null, principal.getPrincipalId());
        }
        if (mappings.size() > 1) {
            return deny(audit, AdmissionReason.BINDING_CONFLICT, BindStatus.CONFLICT, null, null, principal.getPrincipalId());
        }
        PrincipalAssetMapping mapping = mappings.get(0);

        // 3. 证书吊销/身份/有效期（FW-SEC，fail-closed）
        CertificateVerificationAdapter.CertificateVerificationResult verification;
        try {
            verification = certificateVerificationAdapter.verify(request.getLeafCertificateDer(), request.getCertSerial(),
                    request.getCertFingerprint(), decisionAt);
        } catch (Exception e) {
            log.warn("PKI证书状态查询依赖不可用，fail-closed: decisionId={}, err={}", decisionId, e.getMessage());
            audit.setPkiLatencyMs(System.currentTimeMillis() - decisionAt.toEpochMilli());
            return deny(audit, AdmissionReason.DEPENDENCY_UNAVAILABLE, BindStatus.BOUND, CertificateStatus.UNKNOWN,
                    null, principal.getPrincipalId());
        }
        if (verification.status() == CertificateStatus.REVOKED) {
            return deny(audit, AdmissionReason.CERT_REVOKED, BindStatus.BOUND, CertificateStatus.REVOKED,
                    null, principal.getPrincipalId());
        }
        if (verification.status() == CertificateStatus.UNKNOWN) {
            return deny(audit, AdmissionReason.DEPENDENCY_UNAVAILABLE, BindStatus.BOUND, CertificateStatus.UNKNOWN,
                    null, principal.getPrincipalId());
        }
        // CN ↔ uid 业务比较归 VIAM（与 TSP 一致）
        if (!ViamUtils.normalizeUid(verification.subjectCommonName()).equals(uid)) {
            return deny(audit, AdmissionReason.IDENTITY_MISMATCH, BindStatus.BOUND, CertificateStatus.VALID,
                    null, principal.getPrincipalId());
        }
        if (verification.notAfter() != null && decisionAt.isAfter(verification.notAfter())) {
            return deny(audit, AdmissionReason.CERT_EXPIRED, BindStatus.BOUND, CertificateStatus.EXPIRED,
                    null, principal.getPrincipalId());
        }
        audit.setPkiLatencyMs(verification.pkiLatencyMs());

        // 4. 安全开通准入态
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principal.getPrincipalId()).orElse(null);
        DeviceStatus deviceStatus = mapOnboardingState(onboarding);
        if (deviceStatus == DeviceStatus.BLOCKED) {
            return deny(audit, AdmissionReason.DEVICE_BLOCKED, BindStatus.BOUND, CertificateStatus.VALID,
                    DeviceStatus.BLOCKED, principal.getPrincipalId());
        }
        if (deviceStatus == DeviceStatus.RETIRED) {
            return deny(audit, AdmissionReason.DEVICE_RETIRED, BindStatus.BOUND, CertificateStatus.VALID,
                    DeviceStatus.RETIRED, principal.getPrincipalId());
        }
        if (deviceStatus == null) {
            return deny(audit, AdmissionReason.DEPENDENCY_UNAVAILABLE, BindStatus.BOUND, CertificateStatus.VALID,
                    null, principal.getPrincipalId());
        }

        // 5. ALLOW（仅准入通过；成功接入需可信 connected 证据）
        audit.setVin(mapping.getVin());
        audit.setDecision(AdmissionDecision.ALLOW.name());
        audit.setReason(AdmissionReason.NONE.name());
        audit.setBindStatus(BindStatus.BOUND.name());
        audit.setCertStatus(CertificateStatus.VALID.name());
        audit.setDeviceStatus(deviceStatus.name());
        audit.setBindVersion(mapping.getBindingVersion());
        // 不可变准入快照（成功接入证据；D-VIAM-007）
        audit.setSnapshotDigest(ViamUtils.sha256Hex(
                decisionId + "|" + mapping.getVin() + "|" + mapping.getBindingVersion()
                        + "|" + request.getCertSerial() + "|" + request.getCertFingerprint()));
        audit.setSnapshotExpiresAt(decisionAt.plusSeconds(snapshotMaxAgeSeconds()));
        return audit;
    }

    /**
     * 安全开通准入态映射。
     */
    private DeviceStatus mapOnboardingState(DeviceOnboarding onboarding) {
        if (onboarding == null || onboarding.getState() == null) {
            return null;
        }
        switch (onboarding.getState()) {
            case PRE_ACTIVE:
            case ACTIVATING:
            case ACTIVE:
                return DeviceStatus.valueOf(onboarding.getState().name());
            case BLOCKED:
                return DeviceStatus.BLOCKED;
            case RETIRED:
                return DeviceStatus.RETIRED;
            default:
                return null;
        }
    }

    private DecisionAudit deny(DecisionAudit audit, AdmissionReason reason, BindStatus bindStatus,
                               CertificateStatus certStatus, DeviceStatus deviceStatus, String principalId) {
        audit.setDecision(AdmissionDecision.DENY.name());
        audit.setReason(reason.name());
        audit.setBindStatus(bindStatus == null ? null : bindStatus.name());
        audit.setCertStatus(certStatus == null ? null : certStatus.name());
        audit.setDeviceStatus(deviceStatus == null ? null : deviceStatus.name());
        return audit;
    }
}
