package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningBatchPo;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningItemPo;

import java.time.ZoneId;

/**
 * 业务密钥开通批次转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class ProvisioningBatchConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private ProvisioningBatchConverter() {
    }

    public static ProvisioningBatchPo toPo(ProvisioningBatch e) {
        return ProvisioningBatchPo.builder()
                .requestId(e.getRequestId())
                .requestDigest(e.getRequestDigest())
                .ackDigest(e.getAckDigest())
                .deviceSn(e.getDeviceSn())
                .bindingId(e.getBindingId())
                .partId(e.getPartId())
                .hsmUidDigest(e.getHsmUidDigest())
                .certificateSnDigest(e.getCertificateSnDigest())
                .businessDomain(e.getBusinessDomain())
                .status(e.getStatus() == null ? null : e.getStatus().name())
                .failReason(e.getFailReason())
                .responsePayload(e.getResponsePayload())
                .responseRef(e.getResponseRef())
                .responseDigest(e.getResponseDigest())
                .responseCodecVersion(e.getResponseCodecVersion())
                .responsePersistedAt(toLdt(e.getResponsePersistedAt()))
                .lifecycleProfile(e.getLifecycleProfile())
                .firstIssuedAt(toLdt(e.getFirstIssuedAt()))
                .ackDeadlineAt(toLdt(e.getAckDeadlineAt()))
                .immutableContentDigest(e.getImmutableContentDigest())
                .leaseSeq(e.getLeaseSeq())
                .terminalReason(e.getTerminalReason())
                .terminalAt(toLdt(e.getTerminalAt()))
                .startedAt(toLdt(e.getStartedAt()))
                .acknowledgedAt(toLdt(e.getAcknowledgedAt()))
                .completedAt(toLdt(e.getCompletedAt()))
                .build();
    }

    public static ProvisioningBatch toEntity(ProvisioningBatchPo po) {
        if (po == null) {
            return null;
        }
        return ProvisioningBatch.builder()
                .id(po.getId())
                .requestId(po.getRequestId())
                .requestDigest(po.getRequestDigest())
                .ackDigest(po.getAckDigest())
                .deviceSn(po.getDeviceSn())
                .bindingId(po.getBindingId())
                .partId(po.getPartId())
                .hsmUidDigest(po.getHsmUidDigest())
                .certificateSnDigest(po.getCertificateSnDigest())
                .businessDomain(po.getBusinessDomain())
                .status(po.getStatus() == null ? null : ProvisioningBatch.BatchState.valueOf(po.getStatus()))
                .failReason(po.getFailReason())
                .responsePayload(po.getResponsePayload())
                .responseRef(po.getResponseRef())
                .responseDigest(po.getResponseDigest())
                .responseCodecVersion(po.getResponseCodecVersion())
                .responsePersistedAt(toInstant(po.getResponsePersistedAt()))
                .lifecycleProfile(po.getLifecycleProfile())
                .firstIssuedAt(toInstant(po.getFirstIssuedAt()))
                .ackDeadlineAt(toInstant(po.getAckDeadlineAt()))
                .immutableContentDigest(po.getImmutableContentDigest())
                .leaseSeq(po.getLeaseSeq())
                .terminalReason(po.getTerminalReason())
                .terminalAt(toInstant(po.getTerminalAt()))
                .startedAt(toInstant(po.getStartedAt()))
                .acknowledgedAt(toInstant(po.getAcknowledgedAt()))
                .completedAt(toInstant(po.getCompletedAt()))
                // SEC-VIAM-DSN-CR-002 / D-VIAM-018：破坏性操作乐观锁锚点（只读回填，不参与写入）
                .modifyTime(po.getModifyTime() == null ? null : po.getModifyTime().toInstant())
                .rowVersion(po.getRowVersion())
                .build();
    }

    public static ProvisioningItemPo itemToPo(ProvisioningItem e) {
        return ProvisioningItemPo.builder()
                .provisioningId(e.getProvisioningId())
                .purpose(e.getPurpose())
                .keyId(e.getKeyId())
                .businessKeyVersion(e.getBusinessKeyVersion())
                .directoryKeyId(e.getDirectoryKeyId())
                .operationId(e.getOperationId())
                .rootKeyVersion(e.getRootKeyVersion())
                .derivationVersion(e.getDerivationVersion())
                .recipientCertFingerprintDigest(e.getRecipientCertFingerprintDigest())
                .envelopeFormat(e.getEnvelopeFormat())
                .wrappingSuite(e.getWrappingSuite())
                .coreEnvelopeDigest(e.getCoreEnvelopeDigest())
                .wireEnvelopeDigest(e.getWireEnvelopeDigest())
                .aadProfileId(e.getAadProfileId())
                .parametersDigest(e.getParametersDigest())
                .wrappedKeyDigest(e.getWrappedKeyDigest())
                .recipientCertDigest(e.getRecipientCertDigest())
                .itemWireOffset(e.getItemWireOffset())
                .itemWireLength(e.getItemWireLength())
                .deviceResult(e.getDeviceResult() == null ? null : e.getDeviceResult().name())
                .importProofDigest(e.getImportProofDigest())
                .confirmedAt(toLdt(e.getConfirmedAt()))
                .build();
    }

    public static ProvisioningItem itemToEntity(ProvisioningItemPo po) {
        if (po == null) {
            return null;
        }
        return ProvisioningItem.builder()
                .provisioningId(po.getProvisioningId())
                .purpose(po.getPurpose())
                .keyId(po.getKeyId())
                .businessKeyVersion(po.getBusinessKeyVersion())
                .directoryKeyId(po.getDirectoryKeyId())
                .operationId(po.getOperationId())
                .rootKeyVersion(po.getRootKeyVersion())
                .derivationVersion(po.getDerivationVersion())
                .recipientCertFingerprintDigest(po.getRecipientCertFingerprintDigest())
                .envelopeFormat(po.getEnvelopeFormat())
                .wrappingSuite(po.getWrappingSuite())
                .coreEnvelopeDigest(po.getCoreEnvelopeDigest())
                .wireEnvelopeDigest(po.getWireEnvelopeDigest())
                .aadProfileId(po.getAadProfileId())
                .parametersDigest(po.getParametersDigest())
                .wrappedKeyDigest(po.getWrappedKeyDigest())
                .recipientCertDigest(po.getRecipientCertDigest())
                .itemWireOffset(po.getItemWireOffset())
                .itemWireLength(po.getItemWireLength())
                .deviceResult(po.getDeviceResult() == null ? null : ProvisioningItem.DeviceResult.valueOf(po.getDeviceResult()))
                .importProofDigest(po.getImportProofDigest())
                .confirmedAt(toInstant(po.getConfirmedAt()))
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
