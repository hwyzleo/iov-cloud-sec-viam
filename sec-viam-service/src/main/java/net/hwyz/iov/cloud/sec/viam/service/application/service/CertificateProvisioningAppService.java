package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertEnrollmentAdapter;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 设备证书生命周期应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-002 / D-VIAM-004）
 * <p>
 * 迁入 VMD CertificateProvisioningAppService 的证书申请/安装/补偿语义与目录职能；
 * 保留 Profile/CSR 意图校验、签发后复验、结果未知恢复。PKI/CA 仍负责实际签发及吊销权威。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateProvisioningAppService {

    private final CredentialEnrollmentRepository enrollmentRepository;
    private final SecurityPrincipalRepository principalRepository;
    private final CertEnrollmentAdapter certEnrollmentAdapter;

    /**
     * 申请设备证书（幂等占位 + 同步签发；不跨慢网络 I/O 持事务）。
     */
    public CertificateApplyResultVo apply(CertificateApplyVo cmd) {
        log.info("申请设备证书: requestId={}, vin={}, deviceSn={}, profile={}",
                cmd.getRequestId(), cmd.getVin(), cmd.getDeviceSn(), cmd.getCertificateProfile());

        // 1. 幂等检查（request_id 占位）
        CredentialEnrollment existing = enrollmentRepository.findByRequestId(cmd.getRequestId()).orElse(null);
        if (existing != null) {
            return buildApplyResult(existing, null);
        }

        // 2. 主体校验（受信身份）
        SecurityPrincipal principal = resolvePrincipal(cmd);
        if (principal.getState() != SecurityPrincipal.PrincipalState.ACTIVE) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_VIN_NOT_EXIST);
        }

        // 3. 同身份同公钥幂等复用
        CredentialEnrollment reused = enrollmentRepository.findByVinAndUidAndSpkiAndProfile(
                cmd.getVin(), principal.getHsmUid(), null, cmd.getCertificateProfile()).orElse(null);
        if (reused != null && reused.isReusableStatus()) {
            return buildApplyResult(reused, null);
        }

        // 4. 建占位行（REQUESTED）
        CredentialEnrollment enrollment = CredentialEnrollment.builder()
                .requestId(cmd.getRequestId())
                .vin(cmd.getVin())
                .deviceCategory(cmd.getDeviceCategory())
                .deviceSn(cmd.getDeviceSn())
                .hsmUid(principal.getHsmUid())
                .certificateProfile(cmd.getCertificateProfile())
                .certStatus(CredentialEnrollment.CertificateState.REQUESTED)
                .sourceSystem(cmd.getSourceSystem())
                .originalRequestId(cmd.getOriginalRequestId())
                .compensationReason(cmd.getCompensationReason())
                .ticketNo(cmd.getTicketNo())
                .facilityNo(cmd.getFacilityNo())
                .lineCode(cmd.getLineCode())
                .build();
        try {
            enrollmentRepository.insert(enrollment);
        } catch (DuplicateKeyException e) {
            CredentialEnrollment raced = enrollmentRepository.findByRequestId(cmd.getRequestId()).orElse(null);
            if (raced != null) {
                return buildApplyResult(raced, null);
            }
            throw e;
        }

        // 5. 调用 FW-SEC 证书注册模板申请（事务外；结果未知转 PENDING_RECONCILE）
        try {
            certEnrollmentAdapter.apply(enrollment, cmd.getCsrDerBase64());
        } catch (net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException e) {
            log.warn("证书申请结果未知，转待对账: requestId={}", cmd.getRequestId());
            enrollment.markPendingReconcile(e.getMessage());
            enrollmentRepository.update(enrollment);
        } catch (Exception e) {
            log.error("证书申请失败: requestId={}", cmd.getRequestId(), e);
            enrollment.markFailed(e.getMessage());
            enrollmentRepository.update(enrollment);
            throw e;
        }

        return buildApplyResult(enrollment, null);
    }

    /**
     * 人工补偿/对账（MPT）：PENDING_RECONCILE/FAILED 状态经 CSR 重发或 PKI 对账推进。
     * <p>
     * 结果未知禁止自动重签，转 PENDING_RECONCILE；终态不得回退。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateApplyResultVo reconcile(String requestId, String csrDerBase64) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        if (enrollment.getCertStatus() != CredentialEnrollment.CertificateState.PENDING_RECONCILE
                && enrollment.getCertStatus() != CredentialEnrollment.CertificateState.FAILED
                && enrollment.getCertStatus() != CredentialEnrollment.CertificateState.ISSUING) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_COMPENSATION_NOT_ALLOWED);
        }
        if (enrollment.getCertStatus() == CredentialEnrollment.CertificateState.FAILED && csrDerBase64 != null) {
            // 失败重试：按原 requestId/idempotencyKey 重新 apply
            try {
                certEnrollmentAdapter.apply(enrollment, csrDerBase64);
                enrollmentRepository.update(enrollment);
            } catch (net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException e) {
                enrollment.markPendingReconcile(e.getMessage());
                enrollmentRepository.update(enrollment);
            } catch (Exception e) {
                enrollment.markFailed(e.getMessage());
                enrollmentRepository.update(enrollment);
                throw e;
            }
        } else if (enrollment.getPkiRequestId() != null) {
            // 有 pki_request_id：getStatus/getCertificate 对账推进
            try {
                certEnrollmentAdapter.reconcile(enrollment);
                enrollmentRepository.update(enrollment);
            } catch (Exception e) {
                log.warn("对账查询PKI状态失败，转待对账: requestId={}", requestId, e);
                enrollment.markPendingReconcile(e.getMessage());
                enrollmentRepository.update(enrollment);
            }
        } else {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_MATERIAL_UNAVAILABLE,
                    "无 pki_request_id 且无 CSR，无法自动推进，请人工补申请");
        }
        return buildApplyResult(enrollment, null);
    }

    /**
     * 查询证书申请状态（ISSUING 时尝试对账推进）。
     */
    public CertificateStatusVo status(String requestId) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        if (enrollment.getCertStatus() == CredentialEnrollment.CertificateState.ISSUING
                && enrollment.getPkiRequestId() != null) {
            try {
                certEnrollmentAdapter.reconcile(enrollment);
            } catch (Exception e) {
                log.warn("状态查询对账失败: requestId={}", requestId, e);
            }
        }
        return buildStatusVo(enrollment);
    }

    /**
     * 确认证书安装（事务内：作废同设备同 Profile 既有 ACTIVE 后激活）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void confirmInstalled(CertificateConfirmInstalledVo cmd) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(cmd.getRequestId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        if (enrollment.getCertStatus() != CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED
                && enrollment.getCertStatus() != CredentialEnrollment.CertificateState.INSTALL_FAILED) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_STATUS_NOT_ALLOWED);
        }
        if ("SUCCESS".equals(cmd.getResult())) {
            enrollmentRepository.supersedeActiveByDeviceSnAndProfile(
                    enrollment.getDeviceSn(), enrollment.getCertificateProfile(), enrollment.getRequestId());
            enrollment.confirmInstalled();
        } else {
            enrollment.confirmInstallFailed(cmd.getFailReason());
        }
        enrollment.setLastOperator(cmd.getOperatorId());
        enrollment.setLastOperationAt(Instant.now());
        enrollmentRepository.update(enrollment);
    }

    /**
     * 按证书序列号查询。
     */
    public CertificateStatusVo getByCertSn(String certSn) {
        CredentialEnrollment enrollment = enrollmentRepository.findByCertSn(ViamUtils.canonicalCertSn(certSn))
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        return buildStatusVo(enrollment);
    }

    /**
     * 查询更新时间大于指定时间的证书列表（对账）。
     */
    public List<CertificateStatusVo> listChanged(Instant updatedAfter, int limit) {
        return enrollmentRepository.listUpdatedAfter(updatedAfter, limit).stream()
                .map(this::buildStatusVo)
                .toList();
    }

    private SecurityPrincipal resolvePrincipal(CertificateApplyVo cmd) {
        // 受信主体登记（VMD事实/迁移/入站）为主；本地无登记时经受信入站登记建立
        SecurityPrincipal principal = principalRepository.findByHsmUid(ViamUtils.normalizeUid(cmd.getEcuUid()))
                .orElse(null);
        if (principal == null) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE);
        }
        return principal;
    }

    private CertificateApplyResultVo buildApplyResult(CredentialEnrollment e, Object unused) {
        return CertificateApplyResultVo.builder()
                .requestId(e.getRequestId())
                .status(e.getCertStatus().name())
                .certSn(e.getCertSn())
                .pkiRequestId(e.getPkiRequestId())
                .issuer(e.getIssuer())
                .fingerprint(e.getCertificateFingerprint())
                .notBefore(e.getNotBefore() == null ? null : e.getNotBefore().toString())
                .notAfter(e.getNotAfter() == null ? null : e.getNotAfter().toString())
                .failReason(e.getFailReason())
                .build();
    }

    private CertificateStatusVo buildStatusVo(CredentialEnrollment e) {
        return CertificateStatusVo.builder()
                .requestId(e.getRequestId())
                .status(e.getCertStatus().name())
                .certSn(e.getCertSn())
                .certificateFingerprint(e.getCertificateFingerprint())
                .issuer(e.getIssuer())
                .notBefore(e.getNotBefore())
                .notAfter(e.getNotAfter())
                .issuedAt(e.getIssuedAt())
                .confirmedAt(e.getConfirmedAt())
                .failReason(e.getFailReason())
                .build();
    }
}
