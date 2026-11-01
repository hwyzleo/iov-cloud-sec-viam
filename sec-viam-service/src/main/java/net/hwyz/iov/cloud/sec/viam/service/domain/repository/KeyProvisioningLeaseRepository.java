package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.KeyProvisioningLease;

import java.util.Optional;

/**
 * KL1 交付租约仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 *
 * @author hwyz_leo
 */
public interface KeyProvisioningLeaseRepository {

    /**
     * 按批次 + 租约序号查询。
     */
    Optional<KeyProvisioningLease> findByProvisioningAndSeq(Long provisioningId, int leaseSeq);

    /**
     * 按 messageId 查询（同一 messageId 不得对应不同 bytes）。
     */
    Optional<KeyProvisioningLease> findByMessageId(String messageId);

    /**
     * 保存。
     */
    void save(KeyProvisioningLease lease);
}
