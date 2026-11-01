package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DecisionAuditPo;

import java.time.ZoneId;

/**
 * 准入裁决审计转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class DecisionAuditConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private DecisionAuditConverter() {
    }

    public static DecisionAuditPo toPo(DecisionAudit entity) {
        return DecisionAuditPo.builder()
                .admissionDecisionId(entity.getAdmissionDecisionId())
                .decision(entity.getDecision())
                .reason(entity.getReason())
                .uidDigest(entity.getUidDigest())
                .certSerialDigest(entity.getCertSerialDigest())
                .sourceIpDigest(entity.getSourceIpDigest())
                .vin(entity.getVin())
                .bindStatus(entity.getBindStatus())
                .certStatus(entity.getCertStatus())
                .deviceStatus(entity.getDeviceStatus())
                .bindVersion(entity.getBindVersion())
                .snapshotDigest(entity.getSnapshotDigest())
                .snapshotExpiresAt(toLdt(entity.getSnapshotExpiresAt()))
                .caller(entity.getCaller())
                .dependencyOutcome(entity.getDependencyOutcome())
                .pkiLatencyMs(entity.getPkiLatencyMs())
                .responseTimeMs(entity.getResponseTimeMs())
                .decisionAt(toLdt(entity.getDecisionAt()))
                .build();
    }

    public static DecisionAudit toEntity(DecisionAuditPo po) {
        if (po == null) {
            return null;
        }
        return DecisionAudit.builder()
                .admissionDecisionId(po.getAdmissionDecisionId())
                .decision(po.getDecision())
                .reason(po.getReason())
                .uidDigest(po.getUidDigest())
                .certSerialDigest(po.getCertSerialDigest())
                .sourceIpDigest(po.getSourceIpDigest())
                .vin(po.getVin())
                .bindStatus(po.getBindStatus())
                .certStatus(po.getCertStatus())
                .deviceStatus(po.getDeviceStatus())
                .bindVersion(po.getBindVersion())
                .snapshotDigest(po.getSnapshotDigest())
                .snapshotExpiresAt(toInstant(po.getSnapshotExpiresAt()))
                .caller(po.getCaller())
                .dependencyOutcome(po.getDependencyOutcome())
                .pkiLatencyMs(po.getPkiLatencyMs())
                .responseTimeMs(po.getResponseTimeMs())
                .decisionAt(toInstant(po.getDecisionAt()))
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
