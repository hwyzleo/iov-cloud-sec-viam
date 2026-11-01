package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceLoginRecordVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnboardingVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceSecurityTimelineAppService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 设备安全时间线/开通状态查询控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-007）
 * <p>
 * 供管理后台与 TSP 只读投影；安全事实不可人工改写。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamServiceConstants.DEVICE_LOGIN_V1)
public class ServiceDeviceLoginController {

    private final DeviceSecurityTimelineAppService timelineAppService;

    /**
     * 按成功接入记录ID查询（安全时间线）。
     */
    @GetMapping("/record/{loginId}")
    public DeviceLoginRecordVo getLoginRecord(@PathVariable("loginId") String loginId) {
        return timelineAppService.getLoginRecord(loginId);
    }

    /**
     * 按主体ID查询安全开通状态。
     */
    @GetMapping("/onboarding/{principalId}")
    public DeviceOnboardingVo getOnboarding(@PathVariable("principalId") String principalId) {
        return timelineAppService.getOnboardingByPrincipalId(principalId);
    }
}
