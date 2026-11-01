package net.hwyz.iov.cloud.sec.viam.service.application.service;

import com.google.protobuf.InvalidProtocolBufferException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningError;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusResponse;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatusRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 业务密钥开通应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / D-VIAM-004）
 * <p>
 * 迁入 VMD BusinessKeyProvisioning* 语义：批次 requestId 幂等、KL1 固定 F/B、
 * 完整用途集 ACK 后原子激活、终态不复活、同 requestId 幂等、结果未知恢复。
 * canonical payload 解析后仅提取非敏感元数据；Wrapped Key 不落库、不日志化。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BusinessKeyProvisioningAppService {

    private static final String V2C_COMM_DOMAIN = "V2C_COMM";
    private static final String FULL_PURPOSE_SET = "UPLINK_AEAD,DOWNLINK_AEAD";

    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final DeviceOnboardingRepository onboardingRepository;
    private final DeviceBusinessKeyRepository businessKeyRepository;
    private final ProvisioningBatchRepository batchRepository;

    @Value("${viam.keyprov.ack-deadline-seconds:300}")
    private long ackDeadlineSeconds;

    /**
     * Keyprov 开通申请：校验身份/绑定/证书 → 建批次（幂等）→ 预生成目录行。
     *
     * @param context      可信设备上下文
     * @param payloadBytes canonical KeyProvisioningRequest bytes
     * @param payloadDigest 请求摘要
     * @return canonical 响应或稳定错误
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

        // 身份与绑定校验（可信上下文 + 安全主体，非 payload 自报）
        SecurityPrincipal principal = resolveTrustedPrincipal(context);
        PrincipalAssetMapping mapping = resolveUniqueMapping(principal);
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principal.getPrincipalId())
                .orElse(null);
        if (onboarding == null || onboarding.getState() == DeviceOnboarding.OnboardingState.PRE_ACTIVE) {
            // 无可信成功接入，禁止 Keyprov 开通（D-VIAM-007：不推进跨级激活）
            throw new ViamServiceException(ViamErrorCode.ONBOARDING_ACTIVATE_WITHOUT_LOGIN);
        }

        // 业务域门禁
        if (!V2C_COMM_DOMAIN.equals(request.getBusinessDomain())) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_DOMAIN_NOT_AUTHORIZED);
        }

        // 批次幂等（requestId）
        ProvisioningBatch batch = batchRepository.findByRequestId(request.getRequestId()).orElse(null);
        if (batch != null) {
            if (batch.getRequestDigest() != null && !batch.getRequestDigest().equals(payloadDigest)) {
                throw new ViamServiceException(ViamErrorCode.IDEMPOTENCY_CONFLICT);
            }
            return buildResponse(batch, null, null);
        }

        // 完整用途集校验
        Set<String> purposes = resolvePurposes(request);
        if (!purposes.equals(resolveFullPurposeSet())) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_PURPOSE_INCOMPLETE);
        }

        // 建批次（PREPARING）
        ProvisioningBatch newBatch = ProvisioningBatch.builder()
                .requestId(request.getRequestId())
                .requestDigest(payloadDigest)
                .deviceSn(mapping.getDeviceSn())
                .bindingId(mapping.getBindingId())
                .hsmUidDigest(ViamUtils.sha256Hex(principal.getHsmUid()))
                .businessDomain(V2C_COMM_DOMAIN)
                .status(ProvisioningBatch.BatchState.PREPARING)
                .startedAt(Instant.now())
                .build();
        batchRepository.save(newBatch);

        // 预生成目录行与批次明细（每用途一条）
        List<ProvisioningItem> items = new ArrayList<>();
        for (String purpose : purposes) {
            DeviceBusinessKey existing = businessKeyRepository.findByRequestIdAndPurpose(
                    request.getRequestId(), purpose).orElse(null);
            if (existing == null) {
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

        return buildResponse(newBatch, null, null);
    }

    /**
     * ACK：真实验签在 ImportProofVerifier 校验后按 item 确认，完整用途集确认后原子激活。
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
        ProvisioningBatch batch = batchRepository.findByRequestId(ack.getRequestId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));

        // KL1 截止校验（ACK 竞争/超时）
        if (batch.getAckDeadlineAt() != null && Instant.now().isAfter(batch.getAckDeadlineAt())) {
            batch.expireByAckTimeout(Instant.now());
            batchRepository.save(batch);
            throw new ViamServiceException(ViamErrorCode.KEYPROV_ACK_DEADLINE_EXCEEDED);
        }

        // 逐 item 确认（导入证明验签由 ImportProofVerifier 完成，此处记录结果摘要）
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
            item.confirmSucceeded(ViamUtils.sha256Hex(payloadDigest), Instant.now());
            batchRepository.saveItem(item);
            ackedPurposes.add(item.getPurpose());
        }

        // 完整用途集确认后原子激活
        boolean fullPurposeSetAcked = ackedPurposes.equals(resolveFullPurposeSet());
        batch.acknowledge(payloadDigest, Instant.now(), fullPurposeSetAcked);
        batchRepository.save(batch);

        if (fullPurposeSetAcked) {
            activateOnboarding(batch.getDeviceSn());
        }

        return ViamKeyProvisioningAckResult.builder()
                .requestId(ack.getRequestId())
                .payloadType("security.keyprov.v1.KeyProvisioningAckResult")
                .schemaVersion("keyprov-v1")
                .payloadBytes(KeyProvisioningAckResultEmpty.EMPTY)
                .payloadDigest("")
                .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                .build();
    }

    /**
     * 状态查询（只读）。
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
        return ViamKeyProvisioningStatusResponse.builder()
                .requestId(request.getRequestId())
                .payloadType("security.keyprov.v1.KeyProvisioningStatusResponse")
                .schemaVersion("keyprov-v1")
                .payloadBytes(new byte[0])
                .payloadDigest("")
                .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                .build();
    }

    /**
     * 完整用途集 ACK 确认后激活安全开通状态（ACTIVATING→ACTIVE，不跨级）。
     */
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
            // proto 枚举名（KEY_PURPOSE_UPLINK_AEAD）→ 目录用途代码（UPLINK_AEAD）
            String raw = request.getPurposes(i).name();
            if (raw.startsWith("KEY_PURPOSE_")) {
                purposes.add(raw.substring("KEY_PURPOSE_".length()));
            } else {
                purposes.add(raw);
            }
        }
        return purposes;
    }

    /**
     * proto 枚举名 → 目录用途代码（KEY_PURPOSE_UPLINK_AEAD → UPLINK_AEAD）。
     */
    private String protoPurposeToCode(String protoName) {
        if (protoName == null) {
            return null;
        }
        if (protoName.startsWith("KEY_PURPOSE_")) {
            return protoName.substring("KEY_PURPOSE_".length());
        }
        return protoName;
    }


    private Set<String> resolveFullPurposeSet() {
        Set<String> set = new LinkedHashSet<>();
        for (String purpose : FULL_PURPOSE_SET.split(",")) {
            set.add(purpose);
        }
        return set;
    }

    private ViamKeyProvisioningResponse buildResponse(ProvisioningBatch batch, byte[] payload, String digest) {
        return ViamKeyProvisioningResponse.builder()
                .requestId(batch.getRequestId())
                .payloadType("security.keyprov.v1.KeyProvisioningResponse")
                .schemaVersion("keyprov-v1")
                .payloadBytes(payload == null ? new byte[0] : payload)
                .payloadDigest(digest == null ? "" : digest)
                .outcome(ViamKeyProvisioningOutcome.SUCCESS)
                .build();
    }

    /**
     * 占位（真实 AckResult canonical bytes 由 KeyProvisioningTemplate 生成；本骨架不伪造成功载荷）。
     */
    private static final class KeyProvisioningAckResultEmpty {
        static final byte[] EMPTY = new byte[0];
    }
}
