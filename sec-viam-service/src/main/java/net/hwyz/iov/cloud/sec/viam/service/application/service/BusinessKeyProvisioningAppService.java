package net.hwyz.iov.cloud.sec.viam.service.application.service;

import com.google.protobuf.InvalidProtocolBufferException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamEventTopics;
import net.hwyz.iov.cloud.sec.viam.api.event.BusinessKeyChangedEvent;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningError;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusResponse;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.BusinessKeyDerivedMaterialService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.BusinessKeyMaterialRouter;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.ImportProofVerifier;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyProvisioningResponseStore;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyprovConstants;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyprovEnvelopeAdapter;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyprovEnvelopeException;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.Kl1Constants;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.Kl1LeaseIssuanceService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.Kl1LifecycleDecide;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyprovWireSerializer;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.DerivedKeyOperationIds;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAckResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatus;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatusRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatusResponse;
import net.hwyz.iov.security.keyprov.v1.KeyPurposeStatus;
import net.hwyz.iov.security.keyprov.v1.ProtocolError;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * 业务密钥开通应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / T04 / G-2）
 * <p>
 * 迁入 VMD 既有实现语义：V2C=DERIVED_ROOT（KeyProvisioningTemplate.deriveAndWrap）、
 * KL1 固定 F/B、租约续签（新 messageId/新 E）与传输重放（同 messageId 原字节）分离、
 * 受控加密冻结证据（不重 Wrap 恢复）、ImportProof 真实验签、完整用途集 ACK 后原子激活、
 * 终态不复活、同 requestId 幂等、结果未知转对账。Provider 调用增量在重放路径恒为 0。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BusinessKeyProvisioningAppService {

    private static final String V2C_COMM_DOMAIN = "V2C_COMM";

    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final DeviceOnboardingRepository onboardingRepository;
    private final DeviceBusinessKeyRepository businessKeyRepository;
    private final ProvisioningBatchRepository batchRepository;
    private final CredentialEnrollmentRepository credentialEnrollmentRepository;
    private final BusinessKeyMaterialRouter materialRouter;
    private final BusinessKeyDerivedMaterialService derivedMaterialService;
    private final KeyprovEnvelopeAdapter envelopeAdapter;
    private final KeyProvisioningResponseStore responseStore;
    private final Kl1LeaseIssuanceService leaseIssuanceService;
    private final ImportProofVerifier importProofVerifier;
    private final ViamOutboxWriter outboxWriter;
    private final ObjectMapper objectMapper;

    @Value("${viam.crypto.provisioning.derived-key.derivation-version:v1}")
    private String derivationVersion;

    @Value("${viam.kafka.topics.business-key-changed:viam.business-key.changed}")
    private String businessKeyTopic;

    @Value("${viam.kafka.topics.tbox-v2c-key-provisioned:viam.tbox-v2c-key-provisioned}")
    private String v2cKeyProvisionedTopic;

    /**
     * Keyprov 开通申请：身份/绑定/证书校验 → 材料模型路由（V2C=DERIVED_ROOT）→ 派生+封装 →
     * 冻结证据 → KL1 租约签发。
     */
    @Transactional(rollbackFor = Exception.class)
    public ViamKeyProvisioningResponse request(ViamAuthenticatedDeviceContext context,
                                               byte[] payloadBytes, String payloadDigest) {
        KeyProvisioningRequest request;
        try {
            request = KeyProvisioningRequest.parseFrom(payloadBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_REQUEST_INVALID);
        }

        SecurityPrincipal principal = resolveTrustedPrincipal(context);
        PrincipalAssetMapping mapping = resolveUniqueMapping(principal);
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principal.getPrincipalId()).orElse(null);
        if (onboarding == null || onboarding.getState() == DeviceOnboarding.OnboardingState.PRE_ACTIVE) {
            throw new ViamServiceException(ViamErrorCode.ONBOARDING_ACTIVATE_WITHOUT_LOGIN);
        }
        if (!V2C_COMM_DOMAIN.equals(request.getBusinessDomain())) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_DOMAIN_NOT_AUTHORIZED);
        }
        // envelope v1 能力协商（fail-closed：未知/UNSPECIFIED/不支持不下发不降级）
        if (envelopeAdapter.negotiateEnvelopeFormat(request) == null) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_REQUEST_INVALID,
                    "不支持的 envelope/wrapping suite 组合");
        }

        // 同 requestId 幂等（KL1：SAME_BATCH → 续租；不同摘要 → 冲突只读对账）
        ProvisioningBatch existing = batchRepository.findByRequestId(request.getRequestId()).orElse(null);
        if (existing != null) {
            if (existing.getRequestDigest() != null && !existing.getRequestDigest().equals(payloadDigest)) {
                throw new ViamServiceException(ViamErrorCode.IDEMPOTENCY_CONFLICT);
            }
            return replay(existing);
        }

        Set<String> purposes = resolvePurposes(request);
        if (!purposes.equals(resolveFullPurposeSet())) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_PURPOSE_INCOMPLETE);
        }

        ProvisioningBatch newBatch = ProvisioningBatch.builder()
                .requestId(request.getRequestId())
                .requestDigest(payloadDigest)
                .deviceSn(mapping.getDeviceSn())
                .bindingId(mapping.getBindingId())
                .partId(mapping.getPartId())
                .hsmUidDigest(ViamUtils.sha256Hex(principal.getHsmUid()))
                .businessDomain(V2C_COMM_DOMAIN)
                .status(ProvisioningBatch.BatchState.PREPARING)
                .startedAt(Instant.now())
                .build();
        batchRepository.save(newBatch);

        List<ProvisioningItem> items = new ArrayList<>();
        for (String purpose : purposes) {
            DeviceBusinessKey existingKey = businessKeyRepository.findByRequestIdAndPurpose(
                    request.getRequestId(), purpose).orElse(null);
            if (existingKey == null) {
                DeviceBusinessKey key = DeviceBusinessKey.builder()
                        .deviceSn(mapping.getDeviceSn())
                        .bindingId(mapping.getBindingId())
                        .partId(mapping.getPartId())
                        .hsmUid(principal.getHsmUid())
                        .businessDomain(V2C_COMM_DOMAIN)
                        .purpose(purpose)
                        .businessKeyVersion(1L)
                        .keyState(DeviceBusinessKey.KeyState.PENDING)
                        .wrapMode("DEVICE_CERT_PUBLIC_KEY")
                        .requestId(request.getRequestId())
                        .requestDigest(payloadDigest)
                        .build();
                businessKeyRepository.save(key);
            }
            ProvisioningItem item = ProvisioningItem.builder()
                    .provisioningId(newBatch.getId())
                    .purpose(purpose)
                    .deviceResult(ProvisioningItem.DeviceResult.PENDING)
                    .build();
            batchRepository.saveItem(item);
            items.add(item);
        }
        newBatch.setItems(items);

        // 派生+封装（V2C=DERIVED_ROOT，禁隐式回退）→ canonical item
        Instant now = Instant.now();
        Map<String, WrappedKeyItem> mapped = deriveAndWrapAll(principal, mapping, request, purposes, now);
        KeyProvisioningResponse response = KeyProvisioningResponse.newBuilder()
                .setRequestId(request.getRequestId())
                .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
                .addAllItems(mapped.values())
                .setExpireAtMs(now.toEpochMilli() + Kl1Constants.RESPONSE_TTL_MS)
                .build();
        byte[] responseBytes = KeyprovWireSerializer.serialize(response);

        // 冻结证据 + F/B/C（不重 Wrap 恢复的前提）
        responseStore.persistKl1(request.getRequestId(), responseBytes, now);
        ProvisioningBatch batch = batchRepository.findByRequestId(request.getRequestId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));
        batch.setStatus(ProvisioningBatch.BatchState.WAIT_DEVICE_ACK);
        batchRepository.save(batch);

        // KL1 首次租约签发（E = min(now+60s, B-30s)；E-now<20s → EXPIRED 无 items）
        Kl1LeaseIssuanceService.LeaseIssueResult issued = leaseIssuanceService.issue(batch, now, true);
        if (issued.expiredNoItems()) {
            return ViamKeyProvisioningResponse.builder()
                    .requestId(request.getRequestId())
                    .payloadType(KeyprovConstants.PAYLOAD_TYPE_RESPONSE)
                    .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                    .payloadBytes(KeyprovWireSerializer.serialize(issued.response()))
                    .payloadDigest(ViamUtils.sha256Hex(KeyprovWireSerializer.serialize(issued.response())))
                    .outcome(ViamKeyProvisioningOutcome.REJECTED)
                    .error(ViamKeyProvisioningError.builder()
                            .code(ViamErrorCode.KEYPROV_ACK_DEADLINE_EXCEEDED.getCode())
                            .message("bundle到期无items可交付，请以原requestId查询Status")
                            .retryable(false).action("DO_NOT_RETRY").build())
                    .build();
        }
        return ViamKeyProvisioningResponse.builder()
                .requestId(request.getRequestId())
                .messageId(issued.messageId())
                .payloadType(KeyprovConstants.PAYLOAD_TYPE_RESPONSE)
                .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                .payloadBytes(issued.deliveryBytes())
                .payloadDigest(ViamUtils.sha256Hex(issued.deliveryBytes()))
                .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                .build();
    }

    /**
     * 同 requestId 幂等重放：绝不再调用 Provider/重 Wrap；KL1 续租按规范签发新租约
     * （新 messageId/新 E），不原封返回旧响应。
     */
    private ViamKeyProvisioningResponse replay(ProvisioningBatch batch) {
        switch (batch.getStatus()) {
            case WAIT_DEVICE_ACK -> {
                byte[] frozen = responseStore.load(batch.getRequestId());
                if (frozen == null) {
                    throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVIDER_CALL_UNKNOWN,
                            "冻结响应缺失，STORE_QUARANTINE（禁止重新 derive 补齐）");
                }
                Kl1LeaseIssuanceService.LeaseIssueResult issued =
                        leaseIssuanceService.issue(batch, Instant.now(), true);
                if (issued.expiredNoItems()) {
                    return ViamKeyProvisioningResponse.builder()
                            .requestId(batch.getRequestId())
                            .payloadType(KeyprovConstants.PAYLOAD_TYPE_RESPONSE)
                            .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                            .payloadBytes(KeyprovWireSerializer.serialize(issued.response()))
                            .payloadDigest(ViamUtils.sha256Hex(KeyprovWireSerializer.serialize(issued.response())))
                            .outcome(ViamKeyProvisioningOutcome.REJECTED)
                            .error(ViamKeyProvisioningError.builder()
                                    .code(ViamErrorCode.KEYPROV_ACK_DEADLINE_EXCEEDED.getCode())
                                    .message("bundle到期无items可交付")
                                    .retryable(false).action("DO_NOT_RETRY").build())
                            .build();
                }
                return ViamKeyProvisioningResponse.builder()
                        .requestId(batch.getRequestId())
                        .messageId(issued.messageId())
                        .payloadType(KeyprovConstants.PAYLOAD_TYPE_RESPONSE)
                        .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                        .payloadBytes(issued.deliveryBytes())
                        .payloadDigest(ViamUtils.sha256Hex(issued.deliveryBytes()))
                        .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                        .build();
            }
            case COMPLETED -> {
                // 已 ACK 完成：按冻结证据原字节重放成功（不再续租）
                byte[] frozen = responseStore.load(batch.getRequestId());
                if (frozen == null) {
                    throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVIDER_CALL_UNKNOWN,
                            "冻结响应缺失，STORE_QUARANTINE");
                }
                return ViamKeyProvisioningResponse.builder()
                        .requestId(batch.getRequestId())
                        .payloadType(KeyprovConstants.PAYLOAD_TYPE_RESPONSE)
                        .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                        .payloadBytes(frozen)
                        .payloadDigest(ViamUtils.sha256Hex(frozen))
                        .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                        .build();
            }
            case FAILED, EXPIRED, RECONCILE_REQUIRED -> {
                throw new ViamServiceException(ViamErrorCode.KEYPROV_TERMINAL_STATE_FROZEN,
                        "批次已进入终态，禁止复活/续租: " + batch.getStatus());
            }
            default -> throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_STATE_NOT_ALLOWED);
        }
    }

    private Map<String, WrappedKeyItem> deriveAndWrapAll(SecurityPrincipal principal, PrincipalAssetMapping mapping,
                                                         KeyProvisioningRequest request, Set<String> purposes,
                                                         Instant now) {
        // 受信设备叶子证书（封装收件人）
        CredentialEnrollment cert = credentialEnrollmentRepository.listByDeviceSn(mapping.getDeviceSn()).stream()
                .filter(c -> c.getCertStatus() == CredentialEnrollment.CertificateState.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.BUSINESS_KEY_DEVICE_CERT_NOT_FOUND));
        BizType bizType = BizType.V2C_COMM_ROOT;
        KeyProvisioningTemplate template = materialRouter.requireDerivedRoot(bizType);
        KeyAnchor anchor = KeyAnchor.vin(mapping.getVin());
        Map<String, WrappedKeyItem> mapped = new HashMap<>();
        for (String purpose : purposes) {
            DeviceBusinessKey directory = businessKeyRepository.findByRequestIdAndPurpose(
                    request.getRequestId(), purpose)
                    .orElseThrow(() -> new ViamServiceException(ViamErrorCode.BUSINESS_KEY_NOT_EXIST));
            long version = directory.getBusinessKeyVersion();
            String operationId = DerivedKeyOperationIds.operationId(request.getRequestId(), purpose, version);
            String idemKey = DerivedKeyOperationIds.idempotencyKey(
                    request.getRequestId(), mapping.getDeviceSn(), purpose, version, derivationVersion);
            Map<String, String> audit = new HashMap<>();
            audit.put("purpose", purpose);
            audit.put("operation", "KEYPROV_DERIVED");
            RecipientRef recipient = new RecipientRef.DeviceCertificate(
                    cert.getCertSn(), cert.getPkiRequestId(), null, null,
                    cert.getCertificateFingerprint(), audit);
            DerivedWrappedKey result;
            try {
                result = template.deriveAndWrap(
                        bizType, anchor, KeyPurpose.valueOf(purpose), recipient,
                        DerivationContext.of(
                                derivationVersion == null ? KeyprovConstants.DERIVATION_VERSION_V1 : derivationVersion,
                                version),
                        operationId, idemKey, request.getRequestId(), V2C_COMM_DOMAIN);
            } catch (Exception e) {
                log.warn("keyprov 派生/封装失败（结果未知或依赖不可用）: requestId={}, purpose={}, err={}",
                        request.getRequestId(), purpose, e.getMessage());
                throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVIDER_CALL_UNKNOWN.getCode(),
                        "Provider 派生/封装失败: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            DeviceBusinessKey canonical = derivedMaterialService.persistOrClaimDerivedMaterial(
                    directory, result, BusinessKeyDerivedMaterialService.BusinessKeyPolicy.v2c(),
                    operationId,
                    new BusinessKeyDerivedMaterialService.ClaimContext(
                            mapping.getDeviceSn(), V2C_COMM_DOMAIN, purpose, bizType.name(),
                            mapping.getVin(), request.getRequestId()));
            mapped.put(purpose, envelopeAdapter.toWrappedKeyItem(
                    request.getRequestId(), V2C_COMM_DOMAIN, canonical, result));
        }
        return mapped;
    }

    /**
     * ACK：ImportProof 真实验签 → KL1 B/终态判定 → 逐 item 确认 → 完整用途集原子激活。
     * <p>
     * ACTIVE 一致重复 ACK 幂等处理（重新鉴权 + 精确 proof 摘要匹配），不重复激活/不发事件；
     * FAILED/EXPIRED 终态不复活。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public ViamKeyProvisioningAckResult ack(ViamAuthenticatedDeviceContext context,
                                            byte[] payloadBytes, String payloadDigest) {
        KeyProvisioningAck ack;
        try {
            ack = KeyProvisioningAck.parseFrom(payloadBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_REQUEST_INVALID);
        }
        ProvisioningBatch batch = batchRepository.findByRequestIdForUpdate(ack.getRequestId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));

        // KL1 ACK 线性化（锁内）
        long nowMs = Instant.now().toEpochMilli();
        long deadlineMs = batch.getAckDeadlineAt() == null ? Long.MAX_VALUE
                : batch.getAckDeadlineAt().toEpochMilli();
        boolean exactRepeat = batch.getAckDigest() != null
                && batch.getAckDigest().equals(payloadDigest);
        Kl1LifecycleDecide.AckDecision decision = Kl1LifecycleDecide.ack(
                "COMPLETED".equals(batch.getStatus().name()) ? "ACTIVE" : batch.getStatus().name(),
                nowMs, deadlineMs, false, exactRepeat);

        if ("ACTIVE".equals(decision.action())) {
            // 一致重复 ACK 幂等返回（不重复激活/不发事件）
            if (decision.shouldActivate()) {
                // 不应发生：ACTIVE 状态不触发激活
            }
            return ackResult(ack.getRequestId(), Instant.ofEpochMilli(nowMs));
        }
        if ("FAILED_ACK_TIMEOUT".equals(decision.action())) {
            if (!"FAILED".equals(batch.getStatus().name())) {
                batch.expireByAckTimeout(Instant.ofEpochMilli(nowMs));
                batchRepository.save(batch);
            }
            throw new ViamServiceException(ViamErrorCode.KEYPROV_ACK_DEADLINE_EXCEEDED,
                    "ACK超过固定截止时间（KL1 B）或批次已失败，终态不复活");
        }

        // ImportProof 真实验签（fail-closed）
        CredentialEnrollment cert = credentialEnrollmentRepository.listByDeviceSn(batch.getDeviceSn()).stream()
                .filter(c -> c.getCertStatus() == CredentialEnrollment.CertificateState.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED,
                        "设备叶子证书登记缺失，无法验签"));
        Map<String, WrappedKeyItem> delivered = deliveredItems(batch);
        importProofVerifier.verifyAll(ack.getItemsList(), delivered, batch.getRequestId(),
                batch.getBusinessDomain(), cert);

        // 逐 item 确认
        List<ProvisioningItem> items = batchRepository.listItemsByProvisioningId(batch.getId());
        if (items == null || items.isEmpty()) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND);
        }
        Set<String> ackedPurposes = new LinkedHashSet<>();
        for (var itemResult : ack.getItemsList()) {
            String purposeCode = protoPurposeToCode(itemResult.getPurpose().name());
            ProvisioningItem item = items.stream()
                    .filter(i -> i.getPurpose().equals(purposeCode))
                    .findFirst()
                    .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_ITEM_MISMATCH));
            if (itemResult.getResult() != KeyImportResult.KEY_IMPORT_RESULT_IMPORTED) {
                throw new ViamServiceException(ViamErrorCode.KEYPROV_IMPORT_FAILED,
                        "设备导入失败: purpose=" + purposeCode + ", result=" + itemResult.getResult());
            }
            item.confirmSucceeded(ViamUtils.sha256Hex(payloadDigest), Instant.now());
            batchRepository.saveItem(item);
            ackedPurposes.add(item.getPurpose());
        }

        boolean fullPurposeSetAcked = ackedPurposes.equals(resolveFullPurposeSet());
        batch.acknowledge(payloadDigest, Instant.ofEpochMilli(nowMs), fullPurposeSetAcked);
        batchRepository.save(batch);
        if (fullPurposeSetAcked) {
            activateOnboarding(batch.getDeviceSn());
            publishV2cKeyProvisioned(batch);
        }
        return ackResult(ack.getRequestId(), Instant.ofEpochMilli(nowMs));
    }

    private ViamKeyProvisioningAckResult ackResult(String requestId, Instant occurredAt) {
        KeyProvisioningAckResult result = KeyProvisioningAckResult.newBuilder()
                .setRequestId(requestId == null ? "" : requestId)
                .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
                .setOccurredAtMs(occurredAt.toEpochMilli())
                .build();
        byte[] bytes = KeyprovWireSerializer.serialize(result);
        return ViamKeyProvisioningAckResult.builder()
                .requestId(requestId)
                .payloadType(KeyprovConstants.PAYLOAD_TYPE_ACK_RESULT)
                .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                .payloadBytes(bytes)
                .payloadDigest(ViamUtils.sha256Hex(bytes))
                .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                .build();
    }

    /**
     * 状态查询（只读，不创建版本、不重放请求）。
     */
    @Transactional(readOnly = true)
    public ViamKeyProvisioningStatusResponse status(ViamAuthenticatedDeviceContext context,
                                                    byte[] payloadBytes, String payloadDigest) {
        KeyProvisioningStatusRequest request;
        try {
            request = KeyProvisioningStatusRequest.parseFrom(payloadBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_REQUEST_INVALID);
        }
        ProvisioningBatch batch = batchRepository.findByRequestId(request.getRequestId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));
        KeyProvisioningStatusResponse.Builder builder = KeyProvisioningStatusResponse.newBuilder()
                .setRequestId(request.getRequestId())
                .setStatus(statusOf(batch))
                .setOccurredAtMs(Instant.now().toEpochMilli());
        // 逐用途状态（keyId/version/import_result）
        List<ProvisioningItem> items = batchRepository.listItemsByProvisioningId(batch.getId());
        if (items != null) {
            for (ProvisioningItem item : items) {
                DeviceBusinessKey key = businessKeyRepository.findByRequestIdAndPurpose(
                        batch.getRequestId(), item.getPurpose()).orElse(null);
                KeyPurposeStatus.Builder ps = KeyPurposeStatus.newBuilder()
                        .setPurpose(protoPurpose(item.getPurpose()));                if (key != null && key.getKeyId() != null) {
                    ps.setKeyId(key.getKeyId());
                    ps.setBusinessKeyVersion(key.getBusinessKeyVersion());
                }
                ps.setImportResult(batch.getStatus() == ProvisioningBatch.BatchState.COMPLETED
                        ? KeyImportResult.KEY_IMPORT_RESULT_IMPORTED
                        : KeyImportResult.KEY_IMPORT_RESULT_UNKNOWN);
                builder.addItems(ps);
            }
        }
        if (batch.getStatus() == ProvisioningBatch.BatchState.FAILED
                || batch.getStatus() == ProvisioningBatch.BatchState.EXPIRED) {
            builder.setError(ProtocolError.newBuilder()
                    .setCode(KeyprovConstants.ERR_EXPIRED)
                    .setRetryable(false)
                    .setAction("DO_NOT_RETRY")
                    .setMessage("批次终态: " + batch.getStatus())
                    .build());
        }
        KeyProvisioningStatusResponse status = builder.build();
        byte[] bytes = KeyprovWireSerializer.serialize(status);
        return ViamKeyProvisioningStatusResponse.builder()
                .requestId(request.getRequestId())
                .payloadType(KeyprovConstants.PAYLOAD_TYPE_STATUS_RESPONSE)
                .schemaVersion(KeyprovConstants.PROTOCOL_VERSION)
                .payloadBytes(bytes)
                .payloadDigest(ViamUtils.sha256Hex(bytes))
                .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                .build();
    }

    private KeyProvisioningStatus statusOf(ProvisioningBatch batch) {
        switch (batch.getStatus()) {
            case COMPLETED:
                return KeyProvisioningStatus.KEY_PROVISIONING_STATUS_ACTIVE;
            case WAIT_DEVICE_ACK:
            case PREPARING:
                return KeyProvisioningStatus.KEY_PROVISIONING_STATUS_ACK_PENDING;
            case FAILED:
            case EXPIRED:
                return KeyProvisioningStatus.KEY_PROVISIONING_STATUS_FAILED;
            case RECONCILE_REQUIRED:
            default:
                return KeyProvisioningStatus.KEY_PROVISIONING_STATUS_UNKNOWN;
        }
    }

    /**
     * 从冻结响应提取逐用途已交付 canonical item（envelopeDigest/KCV 供验签）。
     */
    private Map<String, WrappedKeyItem> deliveredItems(ProvisioningBatch batch) {
        byte[] frozen = responseStore.load(batch.getRequestId());
        if (frozen == null) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_RESPONSE_FROZEN,
                    "冻结响应缺失，无法关联交付 item");
        }
        KeyProvisioningResponse response;
        try {
            response = KeyProvisioningResponse.parseFrom(frozen);
        } catch (Exception e) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_RESPONSE_FROZEN,
                    "冻结响应解析失败（fail-closed）");
        }
        Map<String, WrappedKeyItem> delivered = new HashMap<>();
        for (WrappedKeyItem item : response.getItemsList()) {
            delivered.put(KeyprovConstants.protoPurposeToCode(item.getPurpose()), item);
        }
        return delivered;
    }

    private void activateOnboarding(String deviceSn) {
        PrincipalAssetMapping mapping = mappingRepository.findActiveByDeviceSn(deviceSn).orElse(null);
        if (mapping == null) {
            return;
        }
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(mapping.getPrincipalId()).orElse(null);
        if (onboarding != null && onboarding.getState() == DeviceOnboarding.OnboardingState.ACTIVATING) {
            onboarding.activate(onboarding.getActivateVersion() + 1);
            onboardingRepository.save(onboarding);
            log.info("安全开通已激活: principalId={}", onboarding.getPrincipalId());
        }
    }

    /**
     * V2C 开通完成事件（key=deviceSn，完整用途集聚合事件；仅在首次 ACK 激活时发布）。
     */
    private void publishV2cKeyProvisioned(ProvisioningBatch batch) {
        try {
            String eventId = UUID.randomUUID().toString().replace("-", "");
            BusinessKeyChangedEvent event = new BusinessKeyChangedEvent(
                    eventId,
                    batch.getDeviceSn(),
                    batch.getBusinessDomain(),
                    "PROVISIONED",
                    batch.getRequestId(),
                    Instant.now());
            outboxWriter.enqueue(eventId, BusinessKeyChangedEvent.EVENT_TYPE, "DEVICE_BUSINESS_KEY",
                    batch.getDeviceSn(), v2cKeyProvisionedTopic, batch.getDeviceSn(),
                    objectMapper.writeValueAsString(event), "KEYPROV_ACK", batch.getRequestId());
        } catch (Exception e) {
            log.error("发布V2C开通完成事件失败: requestId={}", batch.getRequestId(), e);
            throw new IllegalStateException("V2C开通完成事件发布失败", e);
        }
    }

    private SecurityPrincipal resolveTrustedPrincipal(ViamAuthenticatedDeviceContext context) {
        if (context == null || context.getHsmUid() == null) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE);
        }
        return principalRepository.findByHsmUid(ViamUtils.normalizeUid(context.getHsmUid()))
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_NOT_EXIST));
    }

    private PrincipalAssetMapping resolveUniqueMapping(SecurityPrincipal principal) {
        List<PrincipalAssetMapping> mappings = mappingRepository.listActiveByPrincipalId(principal.getPrincipalId());
        if (mappings.size() != 1) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_ASSET_MAPPING_CONFLICT);
        }
        return mappings.get(0);
    }

    private Set<String> resolvePurposes(KeyProvisioningRequest request) {
        Set<String> purposes = new LinkedHashSet<>();
        for (int i = 0; i < request.getPurposesCount(); i++) {
            String raw = request.getPurposes(i).name();
            purposes.add(protoPurposeToCode(raw));
        }
        return purposes;
    }

    private String protoPurposeToCode(String protoName) {
        if (protoName == null) {
            return null;
        }
        if (protoName.startsWith("KEY_PURPOSE_")) {
            return protoName.substring("KEY_PURPOSE_".length());
        }
        return protoName;
    }

    private net.hwyz.iov.security.keyprov.v1.KeyPurpose protoPurpose(String code) {
        if ("UPLINK_AEAD".equals(code)) {
            return net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD;
        }
        if ("DOWNLINK_AEAD".equals(code)) {
            return net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD;
        }
        return net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UNSPECIFIED;
    }

    private Set<String> resolveFullPurposeSet() {
        return KeyprovConstants.V2C_PURPOSE_SET;
    }
}
