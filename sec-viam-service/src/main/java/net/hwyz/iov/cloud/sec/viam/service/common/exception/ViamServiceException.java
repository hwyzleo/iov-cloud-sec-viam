package net.hwyz.iov.cloud.sec.viam.service.common.exception;

import net.hwyz.iov.cloud.framework.common.exception.BusinessException;
import net.hwyz.iov.cloud.framework.common.exception.ErrorCode;

/**
 * VIAM 业务异常（SEC-VIAM-DSN-CR-001 §3；统一异常契约见 SEC-VIAM-DSN-CR-005）。
 * <p>
 * 继承框架 {@link BusinessException}，由框架 {@code GlobalExceptionHandler} 单一出口转换：
 * 管理面端点（声明返回 {@code ApiResponse}）返回 HTTP 200 + 702xxx；机器面端点
 * （声明返回裸 DTO/{@code void}，供 Feign 调用）返回错误码声明的非 2xx + 同一错误体。
 * 服务内不得再以 {@code @RestControllerAdvice} 重复映射 702xxx。
 * </p>
 *
 * @author hwyz_leo
 */
public class ViamServiceException extends BusinessException {

    private static final long serialVersionUID = 1L;

    public ViamServiceException(ErrorCode errorCode) {
        super(errorCode);
    }

    public ViamServiceException(ErrorCode errorCode, String detailMessage) {
        super(errorCode, detailMessage == null || detailMessage.isBlank()
                ? errorCode.getMessage() : detailMessage);
    }

    /**
     * 业务错误码（702xxx）；等价于 {@code getErrorCode().getCode()}。
     *
     * @return 错误码
     */
    public String getCode() {
        return getErrorCode().getCode();
    }
}
