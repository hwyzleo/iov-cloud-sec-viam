package net.hwyz.iov.cloud.sec.viam.api.service;

import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.fallback.ViamVehicleAccessIdentityServiceFallbackFactory;
import net.hwyz.iov.cloud.sec.viam.api.vo.VehicleAccessIdentityResultVo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * 车辆接入身份反查服务 Feign 契约（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * 按 VIN 解析当前接入安全身份；resolve 是身份解析，不是准入许可，不替代吊销和业务授权。
 * </p>
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "viamVehicleAccessIdentityService", value = ServiceNameConstants.SEC_VIAM,
        path = ViamServiceConstants.VEHICLE_ACCESS_IDENTITY_V1,
        fallbackFactory = ViamVehicleAccessIdentityServiceFallbackFactory.class)
public interface ViamVehicleAccessIdentityService {

    /**
     * 按 VIN 解析当前接入安全身份
     *
     * @param vin 车辆VIN
     * @return 接入身份解析结果
     */
    @GetMapping("/byVin/{vin}")
    VehicleAccessIdentityResultVo resolveByVin(@PathVariable("vin") String vin);
}
