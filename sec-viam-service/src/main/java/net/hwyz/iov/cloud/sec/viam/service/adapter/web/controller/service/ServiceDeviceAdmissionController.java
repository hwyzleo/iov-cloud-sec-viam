package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamDeviceAdmissionService;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceAdmissionAppService;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 设备接入准入裁决控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * canonical 端点为 {@code POST /api/service/deviceAdmission/v1/decide}；
 * ALLOW 仅表示准入通过，不等于成功建链（成功接入以可信 connected 证据为准）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamServiceConstants.DEVICE_ADMISSION_V1)
public class ServiceDeviceAdmissionController implements ViamDeviceAdmissionService {

    /** 调用方标识（审计） */
    private static final String CALLER_VAGW = "VAGW";

    private final DeviceAdmissionAppService deviceAdmissionAppService;

    @Override
    @PostMapping("/decide")
    public DeviceAdmissionResultVo decide(@RequestBody @Validated DeviceAdmissionCheckVo request) {
        log.info("VIAM准入裁决请求: uidDigest={}", ViamUtils.sha256Hex(request.getUid()));
        return deviceAdmissionAppService.decide(request, CALLER_VAGW);
    }
}
