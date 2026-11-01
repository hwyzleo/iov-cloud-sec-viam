package net.hwyz.iov.cloud.sec.viam.api.vo.keyprov;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 官方 Keyprov Service 状态查询响应（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）。
 * <p>
 * 成功时承载 canonical {@code security.keyprov.v1.KeyProvisioningStatusResponse} bytes，
 * 仅含非敏感状态与逐用途 keyId/version/import_result；不返回 kmsKeyRef、证书或 Wrapped Key。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "payloadBytes")
public class ViamKeyProvisioningStatusResponse {

    /** 原 requestId（幂等/关联） */
    private String requestId;

    /** canonical 下行 payload 类型；成功时为 security.keyprov.v1.KeyProvisioningStatusResponse */
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
