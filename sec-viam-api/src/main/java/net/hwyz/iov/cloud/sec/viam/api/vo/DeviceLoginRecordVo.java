package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 设备成功接入记录VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-005）
 * <p>
 * 设备"成功登录"=本次身份认证/准入通过且实际成功接入云端，不等同于 ALLOW、MQTT PUBACK、
 * 心跳或普通遥测；首末登录记录的权威归 SEC-VIAM。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceLoginRecordVo {

    /** 成功接入记录ID */
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
}
