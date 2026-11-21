package net.hwyz.iov.cloud.sec.viam.api.service;

import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.fallback.ViamDeviceProofServiceFallbackFactory;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 设备证明校验 Feign 契约（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-1）
 * <p>
 * 供 CIAM 在签发 IVI 设备令牌前确认“这台设备是谁、是否可用”；
 * canonical 端点为 {@code POST /api/service/deviceProof/v1/verify}。
 * VIAM 只回答认证结论：不签发令牌、不下发凭据、不返回 VIN、不做业务授权（D-VIAM-3-05/08）。
 * 依赖不可用时保持 fail-closed（{@code valid=false} + {@code DEPENDENCY_UNAVAILABLE}）。
 * </p>
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "viamDeviceProofService", value = ServiceNameConstants.SEC_VIAM,
        path = ViamServiceConstants.DEVICE_PROOF_V1,
        fallbackFactory = ViamDeviceProofServiceFallbackFactory.class)
public interface ViamDeviceProofService {

    /**
     * 校验设备证明。
     *
     * @param request 证明请求（proofType + proof + nonce，deviceId 可选/按类型必填）
     * @return 结论（valid + reasonCode + 已登记主体事实）
     */
    @PostMapping("/verify")
    DeviceProofVerifyResultVo verify(@RequestBody DeviceProofVerifyRequestVo request);
}
