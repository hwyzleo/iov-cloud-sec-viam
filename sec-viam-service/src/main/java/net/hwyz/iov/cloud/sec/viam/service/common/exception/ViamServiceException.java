package net.hwyz.iov.cloud.sec.viam.service.common.exception;

import lombok.Getter;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;

/**
 * VIAM 业务异常（SEC-VIAM-DSN-CR-001 §3）
 * <p>
 * 统一携带 702xxx 稳定错误码；对外映射在分类层维护（ViamLegacyCodeMapping）。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
public class ViamServiceException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String code;
    private final String message;

    public ViamServiceException(ViamErrorCode errorCode) {
        this(errorCode, errorCode.getMessage());
    }

    public ViamServiceException(ViamErrorCode errorCode, String detailMessage) {
        super(detailMessage == null ? errorCode.getMessage() : detailMessage);
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    /**
     * 以显式 702xxx 码构造（供协议/错误分类映射使用）。
     */
    public ViamServiceException(String code, String message) {
        super(message);
        this.code = code;
        this.message = message;
    }
}
