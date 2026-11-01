package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 设备成功接入输入事件（SEC-VIAM-DSN-CR-001 / D-VIAM-007）
 * <p>
 * 由 VAGW {@code vagw.device.online} 提供（EDD-VAGW-DSN-CR-012 的 DEVICE_ONLINE 载荷
 * 增强视图）。普通 DEVICE_ONLINE 消息中 UID、VIN、generation 齐全，不自动等于已证明
 * 本次认证通过；必须携带可关联到本次成功准入的可信等效证据
 * （admissionDecisionId + 不可变准入快照，或等效绑定证据），否则不写成功登录、
 * 不推进 ACTIVATING，进入明确的重试/隔离处理。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceOnlineEvidenceVo {

    /** VAGW 事件ID（原 eventId，去重键） */
    private String eventId;

    /** 事件类型，固定 DEVICE_ONLINE */
    private String eventType;

    /** 归一化 HSM UID */
    private String hsmUid;

    /** 车辆VIN（来自本次准入快照） */
    private String vin;

    /** 会话ID */
    private String sessionId;

    /** 连接代际 */
    private long connectionGeneration;

    /** 证书序列号 */
    private String certSerial;

    /** TBOX SN（可选资产字段） */
    private String tboxSn;

    /** 实际接入发生时间 */
    private Instant occurredAt;

    /** 时间来源（EMQX / VAGW_RECEIVED） */
    private String timeSource;

    // ================= 可信关联证据（D-VIAM-007） =================

    /** VIAM 准入裁决ID（本次成功准入的可信证据；缺失视为证据不完整） */
    private String admissionDecisionId;

    /** 不可变准入快照摘要（可选等效证据；与 admissionDecisionId 至少其一） */
    private String admissionSnapshotDigest;

    /** 绑定版本（本次准入快照的 bindingVersion） */
    private Long bindingVersion;

    /** 准入快照有效期 */
    private Instant admissionSnapshotExpiresAt;

    /** 准入快照VIN（与事件VIN一致性校验） */
    private String admissionVin;

    /** 准入快照证书序列号（与事件 certSerial 一致性校验） */
    private String admissionCertSerial;
}
