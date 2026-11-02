package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;

import java.util.Optional;

/**
 * 业务密钥目录仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 *
 * @author hwyz_leo
 */
public interface DeviceBusinessKeyRepository {

    /**
     * 按 keyId 查询。
     */
    Optional<DeviceBusinessKey> findByKeyId(String keyId);

    /**
     * 按上下文查询 ACTIVE（单 ACTIVE 唯一）。
     */
    Optional<DeviceBusinessKey> findActiveByContext(String deviceSn, String businessDomain, String purpose);

    /**
     * 按 requestId + purpose 查询（幂等）。
     */
    Optional<DeviceBusinessKey> findByRequestIdAndPurpose(String requestId, String purpose);

    /**
     * 按主键查询。
     */
    Optional<DeviceBusinessKey> findById(Long id);

    /**
     * 行锁读取（claim-or-reuse；调用方须在事务内）。
     */
    Optional<DeviceBusinessKey> findByKeyIdForUpdate(String keyId);

    /**
     * 保存。
     */
    void save(DeviceBusinessKey key);
}
