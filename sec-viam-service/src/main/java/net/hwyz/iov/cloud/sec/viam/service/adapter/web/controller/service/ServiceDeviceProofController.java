package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamDeviceProofService;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.security.WorkloadContext;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.security.WorkloadContextHolder;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceProofVerifyAppService;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 设备证明校验控制器（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-1）
 * <p>
 * canonical 端点为 {@code POST /api/service/deviceProof/v1/verify}；供 CIAM 在设备令牌签发前
 * 取得认证结论。只认证不签令牌、不返回 VIN/绑定信息。
 * 调用方身份按平台内网互信口径取自 {@link WorkloadContextHolder}（X-Client-Id 自报），
 * 仅用于审计与限流，不作为拒绝依据；禁止请求体自报 caller。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamServiceConstants.DEVICE_PROOF_V1)
public class ServiceDeviceProofController implements ViamDeviceProofService {

    private final DeviceProofVerifyAppService deviceProofVerifyAppService;

    @Override
    @PostMapping("/verify")
    public DeviceProofVerifyResultVo verify(@RequestBody @Validated DeviceProofVerifyRequestVo request) {
        WorkloadContext caller = WorkloadContextHolder.get();
        String callerId = caller == null ? "UNKNOWN" : caller.clientId();
        log.info("VIAM设备证明校验请求: proofType={}, nonceDigest={}, deviceIdDigest={}, caller={}",
                request.getProofType(), ViamUtils.sha256Hex(request.getNonce()),
                ViamUtils.sha256Hex(request.getDeviceId()), callerId);
        return deviceProofVerifyAppService.verify(request, callerId);
    }
}
