package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SuccessfulDeviceLoginPo;

import java.time.ZoneId;

/**
 * 成功接入记录转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class SuccessfulDeviceLoginConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private SuccessfulDeviceLoginConverter() {
    }

    public static SuccessfulDeviceLoginPo toPo(SuccessfulDeviceLogin entity) {
        return SuccessfulDeviceLoginPo.builder()
                .loginId(entity.getLoginId())
                .principalId(entity.getPrincipalId())
                .hsmUid(entity.getHsmUid())
                .vin(entity.getVin())
                .admissionDecisionId(entity.getAdmissionDecisionId())
                .sessionId(entity.getSessionId())
                .connectionGeneration(entity.getConnectionGeneration())
                .certSerial(entity.getCertSerial())
                .occurredAt(toLdt(entity.getOccurredAt()))
                .timeSource(entity.getTimeSource())
                .eventSource(entity.getEventSource())
                .build();
    }

    public static SuccessfulDeviceLogin toEntity(SuccessfulDeviceLoginPo po) {
        if (po == null) {
            return null;
        }
        return SuccessfulDeviceLogin.builder()
                .loginId(po.getLoginId())
                .principalId(po.getPrincipalId())
                .hsmUid(po.getHsmUid())
                .vin(po.getVin())
                .admissionDecisionId(po.getAdmissionDecisionId())
                .sessionId(po.getSessionId())
                .connectionGeneration(po.getConnectionGeneration())
                .certSerial(po.getCertSerial())
                .occurredAt(toInstant(po.getOccurredAt()))
                .timeSource(po.getTimeSource())
                .eventSource(po.getEventSource())
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
