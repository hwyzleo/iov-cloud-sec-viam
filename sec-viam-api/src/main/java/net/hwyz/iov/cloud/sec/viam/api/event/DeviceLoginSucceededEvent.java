package net.hwyz.iov.cloud.sec.viam.api.event;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

/**
 * 设备成功接入事件载荷（SEC-VIAM-DSN-CR-001 §3 / FR-VIAM-005）
 * <p>
 * Topic：{@code viam.device.login-succeeded}；key=principalId 或稳定 hsmUid
 * （二选一在 schema 登记时固定）。事件为不可变事实，禁止事后改写时间。
 * </p>
 *
 * @author hwyz_leo
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeviceLoginSucceededEvent(
        String eventId,
        String principalId,
        String hsmUid,
        String vin,
        String admissionDecisionId,
        String sessionId,
        long connectionGeneration,
        String certSerial,
        Instant occurredAt,
        String timeSource) {

    public static final String EVENT_TYPE = "DEVICE_LOGIN_SUCCEEDED";
}
