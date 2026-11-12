package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.ProvisioningBatchConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.ProvisioningBatchMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.ProvisioningItemMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningBatchPo;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningItemPo;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 业务密钥开通批次仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class ProvisioningBatchRepositoryImpl implements ProvisioningBatchRepository {

    private final ProvisioningBatchMapper mapper;
    private final ProvisioningItemMapper itemMapper;

    @Override
    public Optional<ProvisioningBatch> findByRequestId(String requestId) {
        return Optional.ofNullable(
                ProvisioningBatchConverter.toEntity(mapper.selectByRequestId(requestId)));
    }

    @Override
    public Optional<ProvisioningBatch> findByRequestIdForUpdate(String requestId) {
        return Optional.ofNullable(
                ProvisioningBatchConverter.toEntity(mapper.selectByRequestIdForUpdate(requestId)));
    }

    @Override
    public Optional<ProvisioningBatch> findOpenByDeviceSnAndDomain(String deviceSn, String businessDomain) {
        return Optional.ofNullable(ProvisioningBatchConverter.toEntity(
                mapper.selectOpenByDeviceSnAndDomain(deviceSn, businessDomain)));
    }

    @Override
    public List<ProvisioningBatch> listByDeviceSnAndDomain(String deviceSn, String businessDomain,
                                                          boolean includeTerminal, int limit) {
        return mapper.selectByDeviceSnAndDomain(deviceSn, businessDomain, includeTerminal, limit).stream()
                .map(ProvisioningBatchConverter::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public void save(ProvisioningBatch batch) {
        ProvisioningBatchPo po = ProvisioningBatchConverter.toPo(batch);
        ProvisioningBatchPo existing = mapper.selectByRequestId(batch.getRequestId());
        if (existing == null) {
            mapper.insert(po);
            batch.setId(po.getId());
        } else {
            po.setId(existing.getId());
            batch.setId(existing.getId());
            // FW-MYSQL-DSN-CR-003：updatePo → updateById；原版本须由 fresh 读取携带（乐观锁 CAS），并检查影响行数
            po.setRowVersion(existing.getRowVersion());
            int updated = mapper.updateById(po);
            if (updated != 1) {
                throw new IllegalStateException("ProvisioningBatch 更新未影响一行: id=" + existing.getId());
            }
        }
    }

    @Override
    public void saveItem(ProvisioningItem item) {
        ProvisioningItemPo po = ProvisioningBatchConverter.itemToPo(item);
        if (po.getId() != null) {
            // FW-MYSQL-DSN-CR-003：updatePo → updateById；原版本经 selectById 携带（乐观锁 CAS），并检查影响行数
            ProvisioningItemPo existingItem = itemMapper.selectById(po.getId());
            if (existingItem != null) {
                po.setRowVersion(existingItem.getRowVersion());
            }
            int updated = itemMapper.updateById(po);
            if (updated != 1) {
                throw new IllegalStateException("ProvisioningItem 更新未影响一行: id=" + po.getId());
            }
            return;
        }
        List<ProvisioningItemPo> existing = itemMapper.selectItemsByProvisioningId(item.getProvisioningId());
        Optional<ProvisioningItemPo> found = existing.stream()
                .filter(e -> e.getPurpose().equals(item.getPurpose()))
                .findFirst();
        if (found.isEmpty()) {
            itemMapper.insert(po);
            item.setId(po.getId());
        } else {
            po.setId(found.get().getId());
            item.setId(found.get().getId());
            // FW-MYSQL-DSN-CR-003：updatePo → updateById；原版本须由 fresh 读取携带（乐观锁 CAS），并检查影响行数
            po.setRowVersion(found.get().getRowVersion());
            int updated = itemMapper.updateById(po);
            if (updated != 1) {
                throw new IllegalStateException("ProvisioningItem 更新未影响一行: id=" + found.get().getId());
            }
        }
    }

    @Override
    public List<ProvisioningItem> listItemsByProvisioningId(Long provisioningId) {
        return itemMapper.selectItemsByProvisioningId(provisioningId).stream()
                .map(ProvisioningBatchConverter::itemToEntity)
                .collect(Collectors.toList());
    }
}
