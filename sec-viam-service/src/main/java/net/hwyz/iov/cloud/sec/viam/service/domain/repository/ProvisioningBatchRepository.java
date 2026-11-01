package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;

import java.util.List;
import java.util.Optional;

/**
 * 业务密钥开通批次仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 *
 * @author hwyz_leo
 */
public interface ProvisioningBatchRepository {

    /**
     * 按 requestId 查询。
     */
    Optional<ProvisioningBatch> findByRequestId(String requestId);

    /**
     * 保存批次（含明细）。
     */
    void save(ProvisioningBatch batch);

    /**
     * 保存明细。
     */
    void saveItem(ProvisioningItem item);

    /**
     * 按批次ID查询明细。
     */
    List<ProvisioningItem> listItemsByProvisioningId(Long provisioningId);
}
