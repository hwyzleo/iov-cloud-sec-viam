package net.hwyz.iov.cloud.sec.viam.api.vo.keyprov;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 官方 Keyprov Service ACK 结果（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）。
 * <p>
 * 成功时承载 canonical {@code security.keyprov.v1.KeyProvisioningAckResult} bytes。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "payloadBytes")
public class ViamKeyProvisioningAckResult {

    /** 原 requestId（幂等/关联） */
    private String requestId;

    /** canonical 下行 payload 类型；成功时为 security.keyprov.v1.KeyProvisioningAckResult */
    private String payloadType;

    /** canonical 协议版本（keyprov-v1） */
    private String schemaVersion;

    /** canonical 下行 payload bytes */
    private byte[] payloadBytes;

    /** 下行 payload 摘要（sha-256 hex） */
    private String payloadDigest;

    /** 结果类别 */
    private ViamKeyProvisioningOutcome outcome;

    /** 失败信息（非敏感） */
    private ViamKeyProvisioningError error;
}
