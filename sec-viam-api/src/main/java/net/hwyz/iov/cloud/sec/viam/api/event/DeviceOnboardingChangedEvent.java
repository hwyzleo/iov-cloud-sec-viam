package net.hwyz.iov.cloud.sec.viam.api.event;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

/**
 * 设备安全开通状态变更事件载荷（SEC-VIAM-DSN-CR-001 §3 / FR-VIAM-006）
 * <p>
 * Topic：{@code viam.device.onboarding.changed}；key 建议继续使用 deviceSn（保持
 * V2C 开通完成事件 key 口径）。完整用途集聚合事件与单 purpose 目录事件分离。
 * </p>
 *
 * @author hwyz_leo
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeviceOnboardingChangedEvent(
        String eventId,
        String principalId,
        String hsmUid,
        String vin,
        String deviceSn,
        String state,
        Instant firstLoginTime,
        Instant lastLoginTime,
        Instant changedAt) {

    public static final String EVENT_TYPE = "DEVICE_ONBOARDING_CHANGED";
}
