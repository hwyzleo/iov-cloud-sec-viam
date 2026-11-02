package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationReason;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationType;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.event.AccessInvalidatedEvent;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.AccessInvalidationRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 访问失效应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / T05 / G-3）
 * <p>
 * 安全状态变更（block/unblock/retire/revoke/unbind/换件）→ 同事务：
 * ① 更新安全状态并单调递增 securityVersion；② 写不可篡改安全操作审计；
 * ③ 建执行跟踪记录（PENDING，effectiveBy = 状态提交时间 F + 生效时限）；
 * ④ 发布 {@code viam.access-invalidated} 事件（双语义：单连接处置/主体级撤销）。
 * unblock 仅恢复重新认证资格，不复活旧 ACL/旧会话；乱序旧事件按安全版本判定不误断新会话。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessInvalidationAppService {

    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final DeviceOnboardingRepository onboardingRepository;
    private final AccessInvalidationRepository invalidationRepository;
    private final SecurityOperationAuditRepository auditRepository;
    private final ViamOutboxWriter outboxWriter;
    private final ObjectMapper objectMapper;

    @Value("${viam.access-invalidation.effective-by-seconds:30}")
    private long effectiveBySeconds;

    @Value("${viam.kafka.topics.access-invalidated:viam.access-invalidated}")
    private String invalidationTopic;

    /**
     * 安全封禁（PRINCIPAL_REVOCATION）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void block(String principalId, String reason, String operatorId, String callerType) {
        SecurityPrincipal principal = requirePrincipal(principalId);
        DeviceOnboarding onboarding = requireOnboarding(principalId);
        try {
            principal.block(reason, Instant.now());
            onboarding.block(reason, Instant.now());
        } catch (IllegalStateException e) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_BLOCK_NOT_ALLOWED, e.getMessage());
        }
        principalRepository.save(principal);
        onboardingRepository.save(onboarding);
        long version = onboarding.getSecurityVersion();
        audit(principal, onboarding, "BLOCK", reason, version, operatorId, callerType);
        publishInvalidation(principal, onboarding, AccessInvalidationReason.BLOCK, version);
    }

    /**
     * 解除封禁：仅恢复重新认证资格；不复活旧 ACL/旧会话（securityVersion 递增）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void unblock(String principalId, String operatorId, String callerType) {
        SecurityPrincipal principal = requirePrincipal(principalId);
        DeviceOnboarding onboarding = requireOnboarding(principalId);
        try {
            principal.unblock();
            onboarding.unblock();
        } catch (IllegalStateException e) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UNBLOCK_NOT_ALLOWED, e.getMessage());
        }
        principalRepository.save(principal);
        onboardingRepository.save(onboarding);
        audit(principal, onboarding, "UNBLOCK", "重新认证资格恢复（不复活旧ACL/旧会话）",
                onboarding.getSecurityVersion(), operatorId, callerType);
    }

    /**
     * 退役（PRINCIPAL_REVOCATION；终态）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void retire(String principalId, String reason, String operatorId, String callerType) {
        SecurityPrincipal principal = requirePrincipal(principalId);
        DeviceOnboarding onboarding = requireOnboarding(principalId);
        try {
            onboarding.retire(reason);
        } catch (IllegalStateException e) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_RETIRE_NOT_ALLOWED, e.getMessage());
        }
        onboardingRepository.save(onboarding);
        long version = onboarding.getSecurityVersion();
        audit(principal, onboarding, "RETIRE", reason, version, operatorId, callerType);
        publishInvalidation(principal, onboarding, AccessInvalidationReason.RETIRE, version);
    }

    /**
     * 解绑/换件（PRINCIPAL_REVOCATION，scope=BINDING；携带 bindingVersion）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void unbind(String principalId, String reason, String operatorId, String callerType) {
        SecurityPrincipal principal = requirePrincipal(principalId);
        List<PrincipalAssetMapping> mappings =
                mappingRepository.listActiveByPrincipalId(principal.getPrincipalId());
        if (mappings.isEmpty()) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_ASSET_MAPPING_NOT_EXIST);
        }
        PrincipalAssetMapping mapping = mappings.get(0);
        mapping.unbind();
        mappingRepository.save(mapping);
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principalId).orElse(null);
        long version = onboarding == null ? 0 : onboarding.getSecurityVersion();
        audit(principal, onboarding, "UNBIND", reason, version, operatorId, callerType);
        publishInvalidation(principal, onboarding, AccessInvalidationReason.UNBIND, version,
                mapping.getBindingVersion());
    }

    /**
     * 单连接处置（CONNECTION_DISPOSAL）：针对指定会话/generation；不得误断更新的合法会话。
     */
    @Transactional(rollbackFor = Exception.class)
    public void connectionDisposal(String principalId, long targetGeneration, String reason,
                                   String operatorId, String callerType) {
        SecurityPrincipal principal = requirePrincipal(principalId);
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principalId).orElse(null);
        long version = onboarding == null ? 0 : onboarding.getSecurityVersion();
        String eventId = ViamOutboxWriter.newEventId();
        AccessInvalidatedEvent event = AccessInvalidatedEvent.builder()
                .eventId(eventId)
                .principalId(principalId)
                .hsmUid(principal.getHsmUid())
                .vin(onboarding == null ? null : onboarding.getVin())
                .deviceSn(onboarding == null ? null : onboarding.getDeviceSn())
                .invalidationType(AccessInvalidationType.CONNECTION_DISPOSAL)
                .reason(AccessInvalidationReason.CONNECTION_DISPOSAL)
                .scope("SESSION")
                .securityVersion(version)
                .targetGeneration(targetGeneration)
                .effectiveAt(Instant.now())
                .effectiveBy(Instant.now().plusSeconds(effectiveBySecondsOrDefault()))
                .source(callerType)
                .operatorId(operatorId)
                .build();
        recordAndPublish(event, reason, version, operatorId, callerType);
    }

    private void publishInvalidation(SecurityPrincipal principal, DeviceOnboarding onboarding,
                                     AccessInvalidationReason reason, long version) {
        publishInvalidation(principal, onboarding, reason, version, null);
    }

    private void publishInvalidation(SecurityPrincipal principal, DeviceOnboarding onboarding,
                                     AccessInvalidationReason reason, long version, Long bindingVersion) {
        Instant now = Instant.now();
        AccessInvalidatedEvent event = AccessInvalidatedEvent.builder()
                .eventId(ViamOutboxWriter.newEventId())
                .principalId(principal.getPrincipalId())
                .hsmUid(principal.getHsmUid())
                .vin(onboarding == null ? null : onboarding.getVin())
                .deviceSn(onboarding == null ? null : onboarding.getDeviceSn())
                .invalidationType(AccessInvalidationType.PRINCIPAL_REVOCATION)
                .reason(reason)
                .scope("PRINCIPAL")
                .securityVersion(version)
                .bindingVersion(bindingVersion)
                .effectiveAt(now)
                .effectiveBy(now.plusSeconds(effectiveBySecondsOrDefault()))
                .source("VIAM")
                .build();
        recordAndPublish(event, reason == null ? null : reason.name(), version, null, "VIAM");
    }

    private void recordAndPublish(AccessInvalidatedEvent event, String detail, long version,
                                  String operatorId, String callerType) {        AccessInvalidationRecord record = AccessInvalidationRecord.builder()
                .invalidationId(event.getEventId())
                .principalId(event.getPrincipalId())
                .hsmUid(event.getHsmUid())
                .vin(event.getVin())
                .deviceSn(event.getDeviceSn())
                .invalidationType(event.getInvalidationType())
                .reason(event.getReason())
                .scope(event.getScope())
                .securityVersion(event.getSecurityVersion())
                .bindingVersion(event.getBindingVersion())
                .targetGeneration(event.getTargetGeneration())
                .effectiveAt(event.getEffectiveAt())
                .effectiveBy(event.getEffectiveBy())
                .status(AccessInvalidationRecord.STATUS_PENDING)
                .retryCount(0)
                .build();
        invalidationRepository.save(record);
        try {
            String payload = objectMapper.writeValueAsString(event);
            record.setEventPayloadDigest(net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.sha256Hex(payload));
            invalidationRepository.save(record);
            outboxWriter.enqueue(event.getEventId(), AccessInvalidatedEvent.EVENT_TYPE, "SECURITY_PRINCIPAL",
                    event.getPrincipalId(), invalidationTopic, event.getPrincipalId(), payload,
                    callerType, operatorId);
        } catch (Exception e) {
            log.error("发布访问失效事件失败: invalidationId={}", event.getEventId(), e);
            throw new IllegalStateException("访问失效事件发布失败", e);
        }
    }

    private void audit(SecurityPrincipal principal, DeviceOnboarding onboarding, String operation,
                       String reason, long version, String operatorId, String callerType) {
        SecurityOperationAudit audit = SecurityOperationAudit.builder()
                .operationId("OP-" + UUID.randomUUID().toString().replace("-", ""))
                .principalId(principal.getPrincipalId())
                .hsmUid(principal.getHsmUid())
                .vin(onboarding == null ? null : onboarding.getVin())
                .deviceSn(onboarding == null ? null : onboarding.getDeviceSn())
                .operation(operation)
                .securityVersion(version)
                .reason(reason)
                .operatorId(operatorId)
                .callerType(callerType)
                .occurredAt(Instant.now())
                .build();
        auditRepository.save(audit);
        log.info("安全操作审计: operation={}, principalId={}, version={}, operator={}",
                operation, principal.getPrincipalId(), version, operatorId);
    }

    private long effectiveBySecondsOrDefault() {
        // 直连构造（单元测试）未注入 @Value 时为 0，回退默认 30s；Spring 注入后使用配置值
        return effectiveBySeconds > 0 ? effectiveBySeconds : 30L;
    }

    private SecurityPrincipal requirePrincipal(String principalId) {
        return principalRepository.findByPrincipalId(principalId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_NOT_EXIST));
    }

    private DeviceOnboarding requireOnboarding(String principalId) {
        return onboardingRepository.findByPrincipalId(principalId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.ONBOARDING_NOT_EXIST));
    }
}
