package net.hwyz.iov.cloud.sec.viam.api.fallback;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamVehicleAccessIdentityService;
import net.hwyz.iov.cloud.sec.viam.api.vo.VehicleAccessIdentityResultVo;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

/**
 * 车辆接入身份反查 Feign 降级工厂（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * 依赖不可用时返回 UNRESOLVED；resolve 不是准入许可，调用方不得以解析失败为据放行。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ViamVehicleAccessIdentityServiceFallbackFactory implements FallbackFactory<ViamVehicleAccessIdentityService> {

    @Override
    public ViamVehicleAccessIdentityService create(Throwable cause) {
        log.warn("VIAM车辆接入身份反查服务不可用: {}", cause.getMessage());
        return new ViamVehicleAccessIdentityService() {
            @Override
            public VehicleAccessIdentityResultVo resolveByVin(String vin) {
                return VehicleAccessIdentityResultVo.builder()
                        .vin(vin)
                        .status("UNRESOLVED")
                        .reason("VIAM_SERVICE_UNAVAILABLE")
                        .build();
            }
        };
    }
}
