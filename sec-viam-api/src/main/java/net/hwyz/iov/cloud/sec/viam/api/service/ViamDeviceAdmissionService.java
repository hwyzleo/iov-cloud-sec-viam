package net.hwyz.iov.cloud.sec.viam.api.service;

import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.fallback.ViamDeviceAdmissionServiceFallbackFactory;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 设备接入准入裁决服务 Feign 契约（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * 目标安全契约唯一源：VAGW/平台调用方只依赖 sec-viam-api 已发布契约，
 * 不复制 Feign/DTO。canonical 端点为 {@code POST /api/service/deviceAdmission/v1/decide}。
 * 依赖不可用时保持 fail-closed（DENY + DEPENDENCY_UNAVAILABLE），不降级为 ALLOW。
 * </p>
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "viamDeviceAdmissionService", value = ServiceNameConstants.SEC_VIAM,
        path = ViamServiceConstants.DEVICE_ADMISSION_V1,
        fallbackFactory = ViamDeviceAdmissionServiceFallbackFactory.class)
public interface ViamDeviceAdmissionService {

    /**
     * 设备接入准入裁决
     *
     * @param request 裁决请求（必须携带本次 mTLS 实际叶子证书）
     * @return 裁决结果
     */
    @PostMapping("/decide")
    DeviceAdmissionResultVo decide(@RequestBody DeviceAdmissionCheckVo request);
}
