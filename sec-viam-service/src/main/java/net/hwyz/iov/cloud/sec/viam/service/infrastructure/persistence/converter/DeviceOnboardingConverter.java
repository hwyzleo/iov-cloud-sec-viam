package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DeviceOnboardingPo;

import java.time.ZoneId;

/**
 * 安全开通状态转换器（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class DeviceOnboardingConverter {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private DeviceOnboardingConverter() {
    }

    public static DeviceOnboardingPo toPo(DeviceOnboarding entity) {
        return DeviceOnboardingPo.builder()
                .principalId(entity.getPrincipalId())
                .hsmUid(entity.getHsmUid())
                .vin(entity.getVin())
                .deviceSn(entity.getDeviceSn())
                .state(entity.getState() == null ? null : entity.getState().name())
                .firstLoginTime(toLdt(entity.getFirstLoginTime()))
                .lastLoginTime(toLdt(entity.getLastLoginTime()))
                .legacyActiveTime(toLdt(entity.getLegacyActiveTime()))
                .blockReason(entity.getBlockReason())
                .blockEffectiveAt(toLdt(entity.getBlockEffectiveAt()))
                .activateVersion(entity.getActivateVersion())
                .securityVersion(entity.getSecurityVersion())
                .build();
    }

    public static DeviceOnboarding toEntity(DeviceOnboardingPo po) {
        if (po == null) {
            return null;
        }
        return DeviceOnboarding.builder()
                .principalId(po.getPrincipalId())
                .hsmUid(po.getHsmUid())
                .vin(po.getVin())
                .deviceSn(po.getDeviceSn())
                .state(po.getState() == null ? null : DeviceOnboarding.OnboardingState.valueOf(po.getState()))
                .firstLoginTime(toInstant(po.getFirstLoginTime()))
                .lastLoginTime(toInstant(po.getLastLoginTime()))
                .legacyActiveTime(toInstant(po.getLegacyActiveTime()))
                .blockReason(po.getBlockReason())
                .blockEffectiveAt(toInstant(po.getBlockEffectiveAt()))
                .activateVersion(po.getActivateVersion())
                .securityVersion(po.getSecurityVersion())
                .build();
    }

    private static java.time.LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private static java.time.Instant toInstant(java.time.LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(UTC).toInstant();
    }
}
