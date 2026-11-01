package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.PrincipalAssetMappingPo;

import java.time.ZoneId;

/**
 * 安全主体资产映射转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class PrincipalAssetMappingConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private PrincipalAssetMappingConverter() {
    }

    public static PrincipalAssetMappingPo toPo(PrincipalAssetMapping entity) {
        return PrincipalAssetMappingPo.builder()
                .principalId(entity.getPrincipalId())
                .vin(entity.getVin())
                .deviceSn(entity.getDeviceSn())
                .bindingId(entity.getBindingId())
                .partId(entity.getPartId())
                .bindingVersion(entity.getBindingVersion())
                .bindingUpdatedAt(toLdt(entity.getBindingUpdatedAt()))
                .deviceCategory(entity.getDeviceCategory())
                .status(entity.getState() == null ? null : entity.getState().name())
                .build();
    }

    public static PrincipalAssetMapping toEntity(PrincipalAssetMappingPo po) {
        if (po == null) {
            return null;
        }
        return PrincipalAssetMapping.builder()
                .principalId(po.getPrincipalId())
                .vin(po.getVin())
                .deviceSn(po.getDeviceSn())
                .bindingId(po.getBindingId())
                .partId(po.getPartId())
                .bindingVersion(po.getBindingVersion())
                .bindingUpdatedAt(toInstant(po.getBindingUpdatedAt()))
                .deviceCategory(po.getDeviceCategory())
                .state(po.getStatus() == null ? null : PrincipalAssetMapping.MappingState.valueOf(po.getStatus()))
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
