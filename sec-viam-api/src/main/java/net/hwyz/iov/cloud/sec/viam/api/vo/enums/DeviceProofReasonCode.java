package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 设备证明校验结论原因码（SEC-VIAM-DSN-CR-003 / D-VIAM-3-03）
 * <p>
 * 四类业务结论显式区分，避免调用方把“依赖故障”当“证明无效”或反之：
 * 只有 {@link #PROOF_VALID} 允许 {@code valid=true}；其余一律 fail-closed。
 * {@link #RATE_LIMITED} 为运维性结论（限流），同样不得视为通过。
 * </p>
 *
 * @author hwyz_leo
 */
public enum DeviceProofReasonCode {

    /** 证明有效：证书/签名、主体登记与安全状态均通过 */
    PROOF_VALID,
    /** 证明无效：证书过期/吊销/链不受信/指纹不符/签名不匹配/未登记证书 */
    PROOF_INVALID,
    /** 主体不可用：设备未登记、已安全封禁或已退役 */
    SUBJECT_UNAVAILABLE,
    /** 依赖不可用：PKI/Redis 不可用、结果不确定或超出总预算（fail-closed） */
    DEPENDENCY_UNAVAILABLE,
    /** 调用频次超限（调用方/设备维度） */
    RATE_LIMITED;

    public static DeviceProofReasonCode valOf(String val) {
        if (val == null) {
            return null;
        }
        return Arrays.stream(values())
                .filter(code -> code.name().equals(val))
                .findFirst()
                .orElse(null);
    }
}
