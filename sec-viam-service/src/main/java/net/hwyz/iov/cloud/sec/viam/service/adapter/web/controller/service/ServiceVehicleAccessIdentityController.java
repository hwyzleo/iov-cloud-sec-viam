package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamVehicleAccessIdentityService;
import net.hwyz.iov.cloud.sec.viam.api.vo.VehicleAccessIdentityResultVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.SecurityPrincipalAppService;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 车辆接入身份反查控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * 按 VIN 解析当前接入安全身份；resolve 是身份解析，不是准入许可，不替代吊销和业务授权。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamServiceConstants.VEHICLE_ACCESS_IDENTITY_V1)
public class ServiceVehicleAccessIdentityController implements ViamVehicleAccessIdentityService {

    private final SecurityPrincipalAppService securityPrincipalAppService;

    @Override
    @GetMapping("/byVin/{vin}")
    public VehicleAccessIdentityResultVo resolveByVin(@PathVariable("vin") String vin) {
        try {
            SecurityPrincipal principal = securityPrincipalAppService.resolvePrincipalByVin(vin);
            PrincipalAssetMapping mapping = securityPrincipalAppService.resolveAccessMappingByVin(vin);
            return VehicleAccessIdentityResultVo.builder()
                    .vin(vin)
                    .status("RESOLVED")
                    .reason("NONE")
                    .hsmUid(principal.getHsmUid())
                    .principalId(principal.getPrincipalId())
                    .tboxSn(mapping == null ? null : mapping.getDeviceSn())
                    .bindingVersion(mapping == null ? null : mapping.getBindingVersion())
                    .bindingUpdatedAt(mapping == null ? null : mapping.getBindingUpdatedAt())
                    .build();
        } catch (Exception e) {
            log.warn("VIN接入身份解析失败: vin={}, err={}", vin, e.getMessage());
            return VehicleAccessIdentityResultVo.builder()
                    .vin(vin)
                    .status("UNRESOLVED")
                    .reason(e.getMessage())
                    .build();
        }
    }
}
