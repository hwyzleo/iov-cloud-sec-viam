package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 成功接入记录实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-005 / D-VIAM-007）
 * <p>
 * 设备"成功登录"=本次身份认证/准入通过且实际成功接入云端，不等同于 ALLOW、MQTT PUBACK、
 * 心跳或普通遥测。本记录以可信 connected 证据（admissionDecisionId/不可变准入快照或
 * 等效绑定证据）为前提，缺证据不得写入。首末登录记录的权威归 SEC-VIAM。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SuccessfulDeviceLogin {

    /** 成功接入记录ID（事件幂等键） */
    private String loginId;

    /** 安全主体ID */
    private String principalId;

    /** 归一化 HSM UID */
    private String hsmUid;

    /** 车辆VIN */
    private String vin;

    /** 关联准入裁决ID（可信证据） */
    private String admissionDecisionId;

    /** 会话ID */
    private String sessionId;

    /** 连接代际 */
    private long connectionGeneration;

    /** 证书序列号（canonical hex） */
    private String certSerial;

    /** 实际接入发生时间（actual connected occurredAt） */
    private Instant occurredAt;

    /** 时间来源（EMQX / VAGW_RECEIVED） */
    private String timeSource;

    /** 事件来源（默认 VAGW_DEVICE_ONLINE） */
    private String eventSource;
}
