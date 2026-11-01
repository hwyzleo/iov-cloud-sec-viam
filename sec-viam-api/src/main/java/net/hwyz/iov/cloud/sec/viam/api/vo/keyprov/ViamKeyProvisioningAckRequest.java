package net.hwyz.iov.cloud.sec.viam.api.vo.keyprov;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 官方 Keyprov Service 设备导入 ACK 请求（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）。
 * <p>
 * {@code payloadBytes} 为 {@code security.keyprov.v1.KeyProvisioningAck} 的 canonical
 * 序列化结果；importProof 位于 payload 内，属敏感材料，禁止 toString/日志/持久化。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "payloadBytes")
public class ViamKeyProvisioningAckRequest {

    /** VAGW 已认证会话派生的可信设备上下文 */
    private ViamAuthenticatedDeviceContext deviceContext;

    /** canonical payload 完整类型名，必须为 security.keyprov.v1.KeyProvisioningAck */
    private String payloadType;

    /** canonical 协议版本（keyprov-v1） */
    private String schemaVersion;

    /** canonical payload bytes（含 importProof，敏感，禁日志） */
    private byte[] payloadBytes;

    /** payload 摘要（sha-256 hex） */
    private String payloadDigest;
}
