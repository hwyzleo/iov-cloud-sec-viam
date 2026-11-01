package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityPrincipalPo;

import java.time.ZoneId;

/**
 * 安全主体转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class SecurityPrincipalConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private SecurityPrincipalConverter() {
    }

    public static SecurityPrincipalPo toPo(SecurityPrincipal entity) {
        return SecurityPrincipalPo.builder()
                .principalId(entity.getPrincipalId())
                .hsmUid(entity.getHsmUid())
                .sourceSystem(entity.getSourceSystem())
                .sourceRefId(entity.getSourceRefId())
                .status(entity.getState() == null ? null : entity.getState().name())
                .blockReason(entity.getBlockReason())
                .blockEffectiveAt(toLdt(entity.getBlockEffectiveAt()))
                .createdAt(toLdt(entity.getCreatedAt()))
                .build();
    }

    public static SecurityPrincipal toEntity(SecurityPrincipalPo po) {
        if (po == null) {
            return null;
        }
        return SecurityPrincipal.builder()
                .principalId(po.getPrincipalId())
                .hsmUid(po.getHsmUid())
                .sourceSystem(po.getSourceSystem())
                .sourceRefId(po.getSourceRefId())
                .state(po.getStatus() == null ? null : SecurityPrincipal.PrincipalState.valueOf(po.getStatus()))
                .blockReason(po.getBlockReason())
                .blockEffectiveAt(toInstant(po.getBlockEffectiveAt()))
                .createdAt(toInstant(po.getCreatedAt()))
                .build();
    }

    static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
