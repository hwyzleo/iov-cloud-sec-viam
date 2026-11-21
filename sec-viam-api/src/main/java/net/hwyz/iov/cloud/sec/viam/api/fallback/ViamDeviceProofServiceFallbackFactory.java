package net.hwyz.iov.cloud.sec.viam.api.fallback;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamDeviceProofService;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofReasonCode;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * 设备证明校验 Feign 降级工厂（SEC-VIAM-DSN-CR-003 / D-VIAM-3-07）
 * <p>
 * 依赖不可用/超时一律 fail-closed：{@code valid=false} + {@code DEPENDENCY_UNAVAILABLE}，
 * 不得降级为通过。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ViamDeviceProofServiceFallbackFactory implements FallbackFactory<ViamDeviceProofService> {

    @Override
    public ViamDeviceProofService create(Throwable cause) {
        log.warn("VIAM设备证明校验服务不可用，fail-closed: {}", cause.getMessage());
        return new ViamDeviceProofService() {
            @Override
            public DeviceProofVerifyResultVo verify(DeviceProofVerifyRequestVo request) {
                return DeviceProofVerifyResultVo.rejected(DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE, Instant.now());
            }
        };
    }
}
