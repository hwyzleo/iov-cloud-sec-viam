package net.hwyz.iov.cloud.sec.viam.api.fallback;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamDeviceAdmissionService;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionDecision;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionReason;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

/**
 * 准入裁决 Feign 降级工厂（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * 依赖不可用/超时一律 fail-closed：DENY + DEPENDENCY_UNAVAILABLE，不降级为 ALLOW，
 * 依赖故障不伪装为吊销。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ViamDeviceAdmissionServiceFallbackFactory implements FallbackFactory<ViamDeviceAdmissionService> {

    @Override
    public ViamDeviceAdmissionService create(Throwable cause) {
        log.warn("VIAM准入裁决服务不可用，fail-closed: {}", cause.getMessage());
        return new ViamDeviceAdmissionService() {
            @Override
            public DeviceAdmissionResultVo decide(DeviceAdmissionCheckVo request) {
                return DeviceAdmissionResultVo.builder()
                        .decision(AdmissionDecision.DENY)
                        .reason(AdmissionReason.DEPENDENCY_UNAVAILABLE)
                        .build();
            }
        };
    }
}
