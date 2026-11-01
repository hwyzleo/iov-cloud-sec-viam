package net.hwyz.iov.cloud.sec.viam.api.vo.keyprov;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * VAGW 已认证 MQTT 会话派生的可信设备上下文（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 * <p>
 * 由 VAGW 从 EMQX 已认证会话生成，与 canonical payload 分离传输；VIAM 不以 payload
 * 自报身份作为授权依据，而是将本上下文与当前安全主体、active 绑定、设备状态和证书状态
 * 交叉校验。本对象不含 Wrapped Key、parameters、importProof 等敏感材料。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ViamAuthenticatedDeviceContext {

    /** 设备序列号（TBOX SN）；仅作交叉校验提示，不作为授权凭证 */
    private String deviceSn;

    /** 归一化 HSM UID；与 ecuUid 至少提供一个，作为定位 active 绑定的权威线索 */
    private String hsmUid;

    /** ECU UID；与 hsmUid 至少提供一个 */
    private String ecuUid;

    /** broker 侧会话标识（审计与旧会话结果防误用） */
    private String brokerSessionId;

    /** 连接代际（重连/session 替换递增） */
    private long connectionGeneration;

    /** 本次会话使用的设备证书序列号（canonical hex，交叉校验） */
    private String certificateSerial;
}
