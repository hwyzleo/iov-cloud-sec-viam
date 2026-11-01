package net.hwyz.iov.cloud.sec.viam.service.infrastructure.vmd;

import net.hwyz.iov.cloud.edd.vmd.api.service.VmdVehiclePartBindingService;
import net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * VMD 绑定事实适配器（SEC-VIAM-DSN-CR-001 / D-VIAM-003）
 * <p>
 * VIAM 直接使用 VMD 官方只读事实查询（{@code VmdVehiclePartBindingService}），
 * 只消费投影，不反向修改绑定、不恢复绑定写入口。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
public class VmdBindingFactAdapter {

    private final VmdVehiclePartBindingService vmdVehiclePartBindingService;

    public VmdBindingFactAdapter(VmdVehiclePartBindingService vmdVehiclePartBindingService) {
        this.vmdVehiclePartBindingService = vmdVehiclePartBindingService;
    }

    /**
     * 按 VIN 查询 active 设备绑定（VMD 事实）。
     */
    public List<VehiclePartBindingExResponse> listActiveBindingsByVin(String vin) {
        return vmdVehiclePartBindingService.listActiveBindingsByVin(vin);
    }

    /**
     * 将 VMD 绑定事实转换为 VIAM 资产映射快照。
     */
    public PrincipalAssetMapping toMapping(String principalId, VehiclePartBindingExResponse binding) {
        return PrincipalAssetMapping.builder()
                .principalId(principalId)
                .vin(binding.getVin())
                .deviceSn(binding.getSn())
                .bindingId(binding.getBindingId())
                .deviceCategory(binding.getDeviceCategory())
                .bindingUpdatedAt(binding.getBindTime())
                .state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build();
    }
}
