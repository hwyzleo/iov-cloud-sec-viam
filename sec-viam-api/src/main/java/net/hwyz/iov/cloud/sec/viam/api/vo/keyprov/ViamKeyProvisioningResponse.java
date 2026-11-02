package net.hwyz.iov.cloud.sec.viam.api.vo.keyprov;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 官方 Keyprov Service 开通申请响应（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）。
 * <p>
 * 成功时承载 canonical {@code security.keyprov.v1.KeyProvisioningResponse} bytes；
 * {@code payloadBytes} 含 Wrapped Key，属敏感材料，仅在单次调用栈短暂存在，
 * 禁止 toString/日志/持久化。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "payloadBytes")
public class ViamKeyProvisioningResponse {

    /** 原 requestId（幂等/关联） */
    private String requestId;

    /** 本次交付租约 messageId（KL1 新交付每次生成；同 messageId 传输重放保持原字节） */
    private String messageId;

    /** canonical 下行 payload 类型；成功时为 security.keyprov.v1.KeyProvisioningResponse */
    private String payloadType;

    /** canonical 协议版本（keyprov-v1） */
    private String schemaVersion;

    /** canonical 下行 payload bytes（敏感，禁日志） */
    private byte[] payloadBytes;

    /** 下行 payload 摘要（sha-256 hex） */
    private String payloadDigest;

    /** 结果类别 */
    private ViamKeyProvisioningOutcome outcome;

    /** 失败信息（非敏感；仅 REJECTED/OUTCOME_UNKNOWN/UNAVAILABLE 时存在） */
    private ViamKeyProvisioningError error;
}
