package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;

import java.time.Instant;
import java.util.Optional;

/**
 * 成功接入记录仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-005）
 *
 * @author hwyz_leo
 */
public interface SuccessfulDeviceLoginRepository {

    /**
     * 按 loginId 查询（事件幂等键）。
     */
    Optional<SuccessfulDeviceLogin> findByLoginId(String loginId);

    /**
     * 保存。
     */
    void save(SuccessfulDeviceLogin login);

    /**
     * 按主体查询首次接入时间。
     */
    Optional<Instant> findFirstLoginTime(String principalId);

    /**
     * 按主体查询最近接入时间。
     */
    Optional<Instant> findLastLoginTime(String principalId);
}
