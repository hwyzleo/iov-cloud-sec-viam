package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DeviceBusinessKeyPo;

import java.time.ZoneId;

/**
 * 设备业务密钥转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class DeviceBusinessKeyConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private DeviceBusinessKeyConverter() {
    }

    public static DeviceBusinessKeyPo toPo(DeviceBusinessKey e) {
        return DeviceBusinessKeyPo.builder()
                .deviceSn(e.getDeviceSn())
                .bindingId(e.getBindingId())
                .partId(e.getPartId())
                .hsmUid(e.getHsmUid())
                .businessDomain(e.getBusinessDomain())
                .purpose(e.getPurpose())
                .materialModel(e.getMaterialModel())
                .keyId(e.getKeyId())
                .businessKeyVersion(e.getBusinessKeyVersion())
                .kmsKeyRef(e.getKmsKeyRef())
                .kmsKeyVersion(e.getKmsKeyVersion())
                .kmsProvider(e.getKmsProvider())
                .rootKeyVersion(e.getRootKeyVersion())
                .derivationVersion(e.getDerivationVersion())
                .algorithm(e.getAlgorithm())
                .keySpec(e.getKeySpec())
                .keyState(e.getKeyState() == null ? null : e.getKeyState().name())
                .validFrom(toLdt(e.getValidFrom()))
                .validTo(toLdt(e.getValidTo()))
                .decryptUntil(toLdt(e.getDecryptUntil()))
                .wrapMode(e.getWrapMode())
                .lastRecipientCertSn(e.getLastRecipientCertSn())
                .requestId(e.getRequestId())
                .operationId(e.getOperationId())
                .supersededById(e.getSupersededById())
                .logicalIdentityDigest(e.getLogicalIdentityDigest())
                .recoveryCount(e.getRecoveryCount())
                .lastRecoveryRequestId(e.getLastRecoveryRequestId())
                .requestDigest(e.getRequestDigest())
                .policyVersion(e.getPolicyVersion())
                .failReason(e.getFailReason())
                .lastAttemptTime(toLdt(e.getLastAttemptTime()))
                .build();
    }

    public static DeviceBusinessKey toEntity(DeviceBusinessKeyPo po) {
        if (po == null) {
            return null;
        }
        return DeviceBusinessKey.builder()
                .deviceSn(po.getDeviceSn())
                .bindingId(po.getBindingId())
                .partId(po.getPartId())
                .hsmUid(po.getHsmUid())
                .businessDomain(po.getBusinessDomain())
                .purpose(po.getPurpose())
                .materialModel(po.getMaterialModel())
                .keyId(po.getKeyId())
                .businessKeyVersion(po.getBusinessKeyVersion())
                .kmsKeyRef(po.getKmsKeyRef())
                .kmsKeyVersion(po.getKmsKeyVersion())
                .kmsProvider(po.getKmsProvider())
                .rootKeyVersion(po.getRootKeyVersion())
                .derivationVersion(po.getDerivationVersion())
                .algorithm(po.getAlgorithm())
                .keySpec(po.getKeySpec())
                .keyState(po.getKeyState() == null ? null : DeviceBusinessKey.KeyState.valueOf(po.getKeyState()))
                .validFrom(toInstant(po.getValidFrom()))
                .validTo(toInstant(po.getValidTo()))
                .decryptUntil(toInstant(po.getDecryptUntil()))
                .wrapMode(po.getWrapMode())
                .lastRecipientCertSn(po.getLastRecipientCertSn())
                .requestId(po.getRequestId())
                .operationId(po.getOperationId())
                .supersededById(po.getSupersededById())
                .logicalIdentityDigest(po.getLogicalIdentityDigest())
                .recoveryCount(po.getRecoveryCount())
                .lastRecoveryRequestId(po.getLastRecoveryRequestId())
                .requestDigest(po.getRequestDigest())
                .policyVersion(po.getPolicyVersion())
                .failReason(po.getFailReason())
                .lastAttemptTime(toInstant(po.getLastAttemptTime()))
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
