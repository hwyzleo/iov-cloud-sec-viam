package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceLoginRecordVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnboardingVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SuccessfulDeviceLoginRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 安全时间线/开通状态查询应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-007 / D-VIAM-009）
 * <p>
 * 用户可见安全管理和运营管理分离：VIAM 提供安全时间线与开通状态查询，
 * TSP 终端管理继续组合运营只读投影。无人工改登录时间、无假成功。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceSecurityTimelineAppService {

    private final SuccessfulDeviceLoginRepository loginRepository;
    private final DeviceOnboardingRepository onboardingRepository;

    /**
     * 按 loginId 查询成功接入记录（安全时间线）。
     */
    @Transactional(readOnly = true)
    public DeviceLoginRecordVo getLoginRecord(String loginId) {
        SuccessfulDeviceLogin login = loginRepository.findByLoginId(loginId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.LOGIN_RECORD_NOT_EXIST));
        return DeviceLoginRecordVo.builder()
                .loginId(login.getLoginId())
                .principalId(login.getPrincipalId())
                .hsmUid(login.getHsmUid())
                .vin(login.getVin())
                .admissionDecisionId(login.getAdmissionDecisionId())
                .sessionId(login.getSessionId())
                .connectionGeneration(login.getConnectionGeneration())
                .certSerial(login.getCertSerial())
                .occurredAt(login.getOccurredAt())
                .timeSource(login.getTimeSource())
                .build();
    }

    /**
     * 按主体ID查询安全开通状态。
     */
    @Transactional(readOnly = true)
    public DeviceOnboardingVo getOnboardingByPrincipalId(String principalId) {
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principalId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.ONBOARDING_NOT_EXIST));
        return DeviceOnboardingVo.builder()
                .principalId(onboarding.getPrincipalId())
                .hsmUid(onboarding.getHsmUid())
                .vin(onboarding.getVin())
                .state(onboarding.getState() == null ? null : onboarding.getState().name())
                .firstLoginTime(onboarding.getFirstLoginTime())
                .lastLoginTime(onboarding.getLastLoginTime())
                .legacyActiveTime(onboarding.getLegacyActiveTime())
                .blockReason(onboarding.getBlockReason())
                .blockEffectiveAt(onboarding.getBlockEffectiveAt())
                .build();
    }
}
