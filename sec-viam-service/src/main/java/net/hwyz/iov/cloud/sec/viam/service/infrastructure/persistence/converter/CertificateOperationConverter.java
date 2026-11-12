package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.CertificateOperationPo;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * 证书人工操作审计转换器（SEC-VIAM-DSN-CR-002 / D-VIAM-013）
 *
 * @author hwyz_leo
 */
public final class CertificateOperationConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private CertificateOperationConverter() {
    }

    public static CertificateOperationPo toPo(CertificateOperation e) {
        return CertificateOperationPo.builder()
                .operationId(e.getOperationId())
                .requestId(e.getRequestId())
                .action(e.getAction() == null ? null : e.getAction().name())
                .operatorId(e.getOperatorId())
                .operatorName(e.getOperatorName())
                .reason(e.getReason())
                .ticketNo(e.getTicketNo())
                .originalRequestId(e.getOriginalRequestId())
                .beforeStatus(e.getBeforeStatus())
                .afterStatus(e.getAfterStatus())
                .requestDigest(e.getRequestDigest())
                .result(e.getResult() == null ? null : e.getResult().name())
                .errorCode(e.getErrorCode())
                .sourceIp(e.getSourceIp())
                .userAgent(e.getUserAgent())
                .occurredAt(toLdt(e.getOccurredAt()))
                .build();
    }

    public static CertificateOperation toEntity(CertificateOperationPo po) {
        if (po == null) {
            return null;
        }
        return CertificateOperation.builder()
                .id(po.getId())
                .operationId(po.getOperationId())
                .requestId(po.getRequestId())
                .action(po.getAction() == null ? null : CertificateOperation.Action.valueOf(po.getAction()))
                .operatorId(po.getOperatorId())
                .operatorName(po.getOperatorName())
                .reason(po.getReason())
                .ticketNo(po.getTicketNo())
                .originalRequestId(po.getOriginalRequestId())
                .beforeStatus(po.getBeforeStatus())
                .afterStatus(po.getAfterStatus())
                .requestDigest(po.getRequestDigest())
                .result(po.getResult() == null ? null : CertificateOperation.Result.valueOf(po.getResult()))
                .errorCode(po.getErrorCode())
                .sourceIp(po.getSourceIp())
                .userAgent(po.getUserAgent())
                .occurredAt(toInstant(po.getOccurredAt()))
                .build();
    }

    private static LocalDateTime toLdt(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, UTC);
    }

    private static Instant toInstant(LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
