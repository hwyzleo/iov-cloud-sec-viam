package net.hwyz.iov.cloud.sec.viam.service.common.exception;

/**
 * 设备证明无效（SEC-VIAM-DSN-CR-003 / 702721）
 * <p>
 * 证书解析/链/有效期/吊销/指纹/签名/nonce 绑定等证明事实不成立。
 * 调用方据此返回 {@code valid=false} + {@code PROOF_INVALID}，不得重试成通过。
 * </p>
 *
 * @author hwyz_leo
 */
public class DeviceProofInvalidException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DeviceProofInvalidException(String message) {
        super(message);
    }

    public DeviceProofInvalidException(String message, Throwable cause) {
        super(message, cause);
    }
}
