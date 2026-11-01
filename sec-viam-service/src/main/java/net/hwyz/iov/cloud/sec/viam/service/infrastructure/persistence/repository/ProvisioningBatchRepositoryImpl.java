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
    public void save(ProvisioningBatch batch) {
        ProvisioningBatchPo po = ProvisioningBatchConverter.toPo(batch);
        ProvisioningBatchPo existing = mapper.selectByRequestId(batch.getRequestId());
        if (existing == null) {
            mapper.insertPo(po);
            batch.setId(po.getId());
        } else {
            po.setId(existing.getId());
            batch.setId(existing.getId());
            mapper.updatePo(po);
        }
    }

    @Override
    public void saveItem(ProvisioningItem item) {
        ProvisioningItemPo po = ProvisioningBatchConverter.itemToPo(item);
        if (po.getId() != null) {
            itemMapper.updatePo(po);
            return;
        }
        List<ProvisioningItemPo> existing = itemMapper.selectItemsByProvisioningId(item.getProvisioningId());
        Optional<ProvisioningItemPo> found = existing.stream()
                .filter(e -> e.getPurpose().equals(item.getPurpose()))
                .findFirst();
        if (found.isEmpty()) {
            itemMapper.insertPo(po);
            item.setId(po.getId());
        } else {
            po.setId(found.get().getId());
            item.setId(found.get().getId());
            itemMapper.updatePo(po);
        }
    }

    @Override
    public List<ProvisioningItem> listItemsByProvisioningId(Long provisioningId) {
        return itemMapper.selectItemsByProvisioningId(provisioningId).stream()
                .map(ProvisioningBatchConverter::itemToEntity)
                .collect(Collectors.toList());
    }
}
