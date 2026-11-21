package net.hwyz.iov.cloud.sec.viam.service.common.exception;

/**
 * 设备证明依赖不可用（SEC-VIAM-DSN-CR-003 / 702724）
 * <p>
 * PKI/Redis 不可用、结果不确定（UNKNOWN）或超出总预算。fail-closed：
 * 调用方返回 {@code valid=false} + {@code DEPENDENCY_UNAVAILABLE} 并允许重试，
 * 绝不降级为通过，也不伪装为“证明无效”。
 * </p>
 *
 * @author hwyz_leo
 */
public class DeviceProofDependencyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DeviceProofDependencyException(String message) {
        super(message);
    }

    public DeviceProofDependencyException(String message, Throwable cause) {
        super(message, cause);
    }
}
