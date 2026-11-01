package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;

import java.util.Optional;

/**
 * 安全开通状态仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-006）
 *
 * @author hwyz_leo
 */
public interface DeviceOnboardingRepository {

    /**
     * 按主体ID查询。
     */
    Optional<DeviceOnboarding> findByPrincipalId(String principalId);

    /**
     * 保存（插入或更新）。
     */
    void save(DeviceOnboarding onboarding);
}
