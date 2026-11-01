package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamEventTopics;
import net.hwyz.iov.cloud.sec.viam.api.event.DeviceLoginSucceededEvent;
import net.hwyz.iov.cloud.sec.viam.api.event.DeviceOnboardingChangedEvent;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnlineEvidenceVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DecisionAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SuccessfulDeviceLoginRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 成功接入记录应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-005 / D-VIAM-007）
 * <p>
 * 设备"成功登录"=本次身份认证/准入通过且实际成功接入云端。普通 DEVICE_ONLINE 消息中
 * UID、VIN、generation 齐全，<b>不自动等于已证明本次认证通过</b>；必须携带可关联到本次
 * 成功准入的可信等效证据（admissionDecisionId + 不可变准入快照，或等效绑定证据），
 * 否则不写成功登录、不推进 ACTIVATING，进入明确的重试/隔离处理。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SuccessfulDeviceLoginAppService {

    private final SuccessfulDeviceLoginRepository loginRepository;
    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final DeviceOnboardingRepository onboardingRepository;
    private final DecisionAuditRepository decisionAuditRepository;
    private final ViamOutboxWriter outboxWriter;
    private final ObjectMapper objectMapper;

    @Value("${viam.login-evidence.snapshot-max-age-minutes:10}")
    private long snapshotMaxAgeMinutes;

    @Value("${viam.kafka.topics.device-login-succeeded:viam.device.login-succeeded}")
    private String loginTopic;

    @Value("${viam.kafka.topics.device-onboarding-changed:viam.device.onboarding.changed}")
    private String onboardingTopic;

    /**
     * 处理 VAGW 设备上线事件（含可信证据校验）。
     *
     * @param evidence 事件载荷（含准入证据）
     * @param sourceTopic 来源 Topic
     * @return 处理结果（LOGIN_RECORDED / EVIDENCE_MISSING / EVIDENCE_REJECTED / DUPLICATE）
     */
    @Transactional(rollbackFor = Exception.class)
    public String handleDeviceOnline(DeviceOnlineEvidenceVo evidence, String sourceTopic) {
        // 1. 可信证据门禁（D-VIAM-007）：普通DEVICE_ONLINE消息字段齐全≠已证明认证通过
        EvidenceCheck check = validateTrustedEvidence(evidence);
        if (!check.trusted()) {
            log.warn("成功接入证据缺失或不可信，进入隔离/重试: eventId={}, reason={}",
                    evidence.getEventId(), check.reason());
            throw new ViamServiceException(ViamErrorCode.LOGIN_EVIDENCE_NOT_TRUSTED, check.reason());
        }

        // 2. 关联准入审计（不可变准入快照）
        DecisionAudit audit = decisionAuditRepository.findByAdmissionDecisionId(evidence.getAdmissionDecisionId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.LOGIN_EVIDENCE_NOT_TRUSTED,
                        "准入裁决ID不存在或审计不可用"));
        if (audit.getSnapshotDigest() == null || audit.getSnapshotExpiresAt() == null
                || audit.getSnapshotExpiresAt().isBefore(Instant.now())) {
            throw new ViamServiceException(ViamErrorCode.LOGIN_EVIDENCE_NOT_TRUSTED,
                    "准入快照不可用或已过期");
        }
        // 快照摘要一致性校验：事件携带的等效证据必须与 VIAM 不可变准入快照匹配（D-VIAM-007）
        if (evidence.getAdmissionSnapshotDigest() != null
                && !evidence.getAdmissionSnapshotDigest().equals(audit.getSnapshotDigest())) {
            throw new ViamServiceException(ViamErrorCode.LOGIN_EVIDENCE_NOT_TRUSTED,
                    "准入快照摘要与VIAM不可变准入快照不一致");
        }
        // 一致性校验：快照VIN/certSerial 与事件匹配
        if (evidence.getAdmissionVin() != null && audit.getVin() != null
                && !evidence.getAdmissionVin().equals(audit.getVin())) {
            throw new ViamServiceException(ViamErrorCode.LOGIN_EVIDENCE_NOT_TRUSTED, "准入快照VIN与事件不一致");
        }

        // 3. 定位安全主体（hsmUid 权威，不接受客户端自报）
        SecurityPrincipal principal = principalRepository.findByHsmUid(ViamUtils.normalizeUid(evidence.getHsmUid()))
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_NOT_EXIST));
        List<PrincipalAssetMapping> mappings = mappingRepository.listActiveByPrincipalId(principal.getPrincipalId());
        if (mappings.size() != 1) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_ASSET_MAPPING_CONFLICT);
        }
        PrincipalAssetMapping mapping = mappings.get(0);

        // 4. generation 防旧（T02：旧generation不写成功记录）
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principal.getPrincipalId())
                .orElseGet(() -> DeviceOnboarding.builder()
                        .principalId(principal.getPrincipalId())
                        .hsmUid(principal.getHsmUid())
                        .vin(mapping.getVin())
                        .deviceSn(mapping.getDeviceSn())
                        .state(DeviceOnboarding.OnboardingState.PRE_ACTIVE)
                        .build());

        // 5. 幂等写入成功接入记录（loginId 由 hsmUid+generation 派生，重连/重放收敛）
        String loginId = ViamUtils.newLoginId(principal.getHsmUid(), evidence.getConnectionGeneration());
        if (loginRepository.findByLoginId(loginId).isPresent()) {
            log.info("成功接入记录已存在，幂等返回: loginId={}", loginId);
            return "DUPLICATE";
        }
        SuccessfulDeviceLogin login = SuccessfulDeviceLogin.builder()
                .loginId(loginId)
                .principalId(principal.getPrincipalId())
                .hsmUid(principal.getHsmUid())
                .vin(mapping.getVin())
                .admissionDecisionId(evidence.getAdmissionDecisionId())
                .sessionId(evidence.getSessionId())
                .connectionGeneration(evidence.getConnectionGeneration())
                .certSerial(ViamUtils.canonicalCertSn(evidence.getCertSerial()))
                .occurredAt(evidence.getOccurredAt())
                .timeSource(evidence.getTimeSource())
                .eventSource("VAGW_DEVICE_ONLINE")
                .build();
        loginRepository.save(login);

        // 6. 推进安全开通状态（PRE_ACTIVE→ACTIVATING；first只写一次，last单调max）
        boolean migrated = onboarding.recordSuccessfulLogin(login.getOccurredAt());
        onboardingRepository.save(onboarding);
        log.info("成功接入记录已写入并推进开通状态: loginId={}, principalId={}, state={}, migrated={}",
                loginId, principal.getPrincipalId(), onboarding.getState(), migrated);

        // 7. 同事务写 Outbox（login-succeeded + onboarding.changed）
        publishLoginEvents(principal, mapping, onboarding, login);

        return migrated ? "LOGIN_RECORDED_MIGRATED" : "LOGIN_RECORDED";
    }

    private void publishLoginEvents(SecurityPrincipal principal, PrincipalAssetMapping mapping,
                                    DeviceOnboarding onboarding, SuccessfulDeviceLogin login) {
        try {
            String loginEventId = UUID.randomUUID().toString().replace("-", "");
            DeviceLoginSucceededEvent loginEvent = new DeviceLoginSucceededEvent(
                    loginEventId,
                    principal.getPrincipalId(),
                    principal.getHsmUid(),
                    mapping.getVin(),
                    login.getAdmissionDecisionId(),
                    login.getSessionId(),
                    login.getConnectionGeneration(),
                    login.getCertSerial(),
                    login.getOccurredAt(),
                    login.getTimeSource());
            outboxWriter.enqueue(loginEventId, DeviceLoginSucceededEvent.EVENT_TYPE, "SECURITY_PRINCIPAL",
                    principal.getPrincipalId(), loginTopic, principal.getPrincipalId(),
                    objectMapper.writeValueAsString(loginEvent), "VAGW_DEVICE_ONLINE", login.getLoginId());

            String onboardingEventId = UUID.randomUUID().toString().replace("-", "");
            DeviceOnboardingChangedEvent onboardingEvent = new DeviceOnboardingChangedEvent(
                    onboardingEventId,
                    principal.getPrincipalId(),
                    principal.getHsmUid(),
                    mapping.getVin(),
                    mapping.getDeviceSn(),
                    onboarding.getState().name(),
                    onboarding.getFirstLoginTime(),
                    onboarding.getLastLoginTime(),
                    Instant.now());
            outboxWriter.enqueue(onboardingEventId, DeviceOnboardingChangedEvent.EVENT_TYPE, "DEVICE_ONBOARDING",
                    principal.getPrincipalId(), onboardingTopic, mapping.getDeviceSn(),
                    objectMapper.writeValueAsString(onboardingEvent), "VAGW_DEVICE_ONLINE", login.getLoginId());
        } catch (Exception e) {
            log.error("发布成功接入事件失败: principalId={}", principal.getPrincipalId(), e);
            throw new IllegalStateException("成功接入事件发布失败", e);
        }
    }

    /**
     * 可信证据校验（D-VIAM-007）。
     * <p>
     * admissionDecisionId 与不可变准入快照摘要二选一（等效证据）；
     * 纯字段齐全（uid/vin/generation）不视为已证明认证通过。
     * </p>
     */
    EvidenceCheck validateTrustedEvidence(DeviceOnlineEvidenceVo evidence) {
        if (evidence == null || evidence.getEventId() == null) {
            return EvidenceCheck.reject("事件ID缺失");
        }
        boolean hasDecisionId = evidence.getAdmissionDecisionId() != null && !evidence.getAdmissionDecisionId().isBlank();
        boolean hasSnapshot = evidence.getAdmissionSnapshotDigest() != null
                && evidence.getAdmissionSnapshotExpiresAt() != null
                && evidence.getAdmissionSnapshotExpiresAt().isAfter(Instant.now());
        if (!hasDecisionId && !hasSnapshot) {
            return EvidenceCheck.reject("缺少admissionDecisionId/不可变准入快照，普通DEVICE_ONLINE字段齐全不等于已证明认证通过");
        }
        if (evidence.getOccurredAt() == null) {
            return EvidenceCheck.reject("实际接入时间缺失");
        }
        if (evidence.getHsmUid() == null || ViamUtils.normalizeUid(evidence.getHsmUid()) == null) {
            return EvidenceCheck.reject("HSM UID缺失");
        }
        if (evidence.getConnectionGeneration() <= 0) {
            return EvidenceCheck.reject("连接代际非法");
        }
        return EvidenceCheck.pass();
    }

    /**
     * 证据校验结果。
     */
    public static final class EvidenceCheck {
        private final boolean trusted;
        private final String reason;

        private EvidenceCheck(boolean trusted, String reason) {
            this.trusted = trusted;
            this.reason = reason;
        }

        public boolean trusted() {
            return trusted;
        }

        public String reason() {
            return reason;
        }

        public static EvidenceCheck pass() {
            return new EvidenceCheck(true, null);
        }

        public static EvidenceCheck reject(String reason) {
            return new EvidenceCheck(false, reason);
        }
    }
}