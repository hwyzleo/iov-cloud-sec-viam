package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.CredentialEnrollmentPo;

import java.time.ZoneId;

/**
 * 设备证书登记转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class CredentialEnrollmentConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private CredentialEnrollmentConverter() {
    }

    public static CredentialEnrollmentPo toPo(CredentialEnrollment e) {
        return CredentialEnrollmentPo.builder()
                .requestId(e.getRequestId())
                .pkiRequestId(e.getPkiRequestId())
                .certSn(e.getCertSn())
                .vin(e.getVin())
                .bindingId(e.getBindingId())
                .partId(e.getPartId())
                .deviceCategory(e.getDeviceCategory())
                .deviceSn(e.getDeviceSn())
                .hsmUid(e.getHsmUid())
                .publicKeySha256(e.getPublicKeySha256())
                .csrFingerprint(e.getCsrFingerprint())
                .certificateProfile(e.getCertificateProfile())
                .subject(e.getSubject())
                .issuer(e.getIssuer())
                .certificateFingerprint(e.getCertificateFingerprint())
                .leafCertificateDigest(e.getLeafCertificateDigest())
                .profileValidatedAt(toLdt(e.getProfileValidatedAt()))
                .certStatus(e.getCertStatus() == null ? null : e.getCertStatus().name())
                .notBefore(toLdt(e.getNotBefore()))
                .notAfter(toLdt(e.getNotAfter()))
                .issuedAt(toLdt(e.getIssuedAt()))
                .confirmedAt(toLdt(e.getConfirmedAt()))
                .failReason(e.getFailReason())
                .sourceSystem(e.getSourceSystem())
                .originalRequestId(e.getOriginalRequestId())
                .compensationReason(e.getCompensationReason())
                .ticketNo(e.getTicketNo())
                .lastOperator(e.getLastOperator())
                .lastOperationAt(toLdt(e.getLastOperationAt()))
                .facilityNo(e.getFacilityNo())
                .lineCode(e.getLineCode())
                .build();
    }

    public static CredentialEnrollment toEntity(CredentialEnrollmentPo po) {
        if (po == null) {
            return null;
        }
        return CredentialEnrollment.builder()
                .requestId(po.getRequestId())
                .pkiRequestId(po.getPkiRequestId())
                .certSn(po.getCertSn())
                .vin(po.getVin())
                .bindingId(po.getBindingId())
                .partId(po.getPartId())
                .deviceCategory(po.getDeviceCategory())
                .deviceSn(po.getDeviceSn())
                .hsmUid(po.getHsmUid())
                .publicKeySha256(po.getPublicKeySha256())
                .csrFingerprint(po.getCsrFingerprint())
                .certificateProfile(po.getCertificateProfile())
                .subject(po.getSubject())
                .issuer(po.getIssuer())
                .certificateFingerprint(po.getCertificateFingerprint())
                .leafCertificateDigest(po.getLeafCertificateDigest())
                .profileValidatedAt(toInstant(po.getProfileValidatedAt()))
                .certStatus(po.getCertStatus() == null ? null : CredentialEnrollment.CertificateState.valueOf(po.getCertStatus()))
                .notBefore(toInstant(po.getNotBefore()))
                .notAfter(toInstant(po.getNotAfter()))
                .issuedAt(toInstant(po.getIssuedAt()))
                .confirmedAt(toInstant(po.getConfirmedAt()))
                .failReason(po.getFailReason())
                .sourceSystem(po.getSourceSystem())
                .originalRequestId(po.getOriginalRequestId())
                .compensationReason(po.getCompensationReason())
                .ticketNo(po.getTicketNo())
                .lastOperator(po.getLastOperator())
                .lastOperationAt(toInstant(po.getLastOperationAt()))
                .facilityNo(po.getFacilityNo())
                .lineCode(po.getLineCode())
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
