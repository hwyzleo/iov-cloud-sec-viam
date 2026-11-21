package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 设备证明校验参数/错误响应（SEC-VIAM-DSN-CR-003 / 702720）
 * <p>
 * 参数缺失等 Bean Validation 失败仍由框架 {@code ValidationExceptionHandler} 返回既有
 * {@code INVALID_PARAM} 语义；本处理器只收敛本控制器抛出的 7027xx 业务异常，
 * 使其以 {@link ApiResponse} 结构（HTTP 200 + code/message）返回，避免落入 500。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE + 100)
@RestControllerAdvice(assignableTypes = ServiceDeviceProofController.class)
public class DeviceProofExceptionHandler {

    @ExceptionHandler(ViamServiceException.class)
    public ApiResponse<Void> handleViamServiceException(ViamServiceException ex) {
        log.warn("设备证明校验参数/业务异常: code={}, message={}", ex.getCode(), ex.getMessage());
        return ApiResponse.<Void>builder()
                .code(ex.getCode())
                .message(ex.getMessage())
                .traceId(MDC.get("traceId"))
                .timestamp(System.currentTimeMillis())
                .build();
    }
}
