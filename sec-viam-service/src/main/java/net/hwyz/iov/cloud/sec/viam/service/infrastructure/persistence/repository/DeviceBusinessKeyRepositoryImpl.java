package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.DeviceBusinessKeyConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.DeviceBusinessKeyMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DeviceBusinessKeyPo;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 设备业务密钥目录仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class DeviceBusinessKeyRepositoryImpl implements DeviceBusinessKeyRepository {

    private final DeviceBusinessKeyMapper mapper;

    @Override
    public Optional<DeviceBusinessKey> findByKeyId(String keyId) {
        return Optional.ofNullable(DeviceBusinessKeyConverter.toEntity(mapper.selectByKeyId(keyId)));
    }

    @Override
    public Optional<DeviceBusinessKey> findActiveByContext(String deviceSn, String businessDomain, String purpose) {
        return Optional.ofNullable(
                DeviceBusinessKeyConverter.toEntity(mapper.selectActiveByContext(deviceSn, businessDomain, purpose)));
    }

    @Override
    public Optional<DeviceBusinessKey> findByRequestIdAndPurpose(String requestId, String purpose) {
        return Optional.ofNullable(
                DeviceBusinessKeyConverter.toEntity(mapper.selectByRequestIdAndPurpose(requestId, purpose)));
    }

    @Override
    public Optional<DeviceBusinessKey> findById(Long id) {
        return Optional.ofNullable(DeviceBusinessKeyConverter.toEntity(mapper.selectById(id)));
    }

    @Override
    public Optional<DeviceBusinessKey> findByKeyIdForUpdate(String keyId) {
        return Optional.ofNullable(DeviceBusinessKeyConverter.toEntity(mapper.selectByKeyIdForUpdate(keyId)));
    }

    @Override
    public void save(DeviceBusinessKey key) {
        DeviceBusinessKeyPo po = DeviceBusinessKeyConverter.toPo(key);
        DeviceBusinessKeyPo existing = mapper.selectByRequestIdAndPurpose(key.getRequestId(), key.getPurpose());
        if (existing == null) {
            mapper.insert(po);
        } else {
            po.setId(existing.getId());
            // FW-MYSQL-DSN-CR-003：updatePo → updateById；原版本须由 fresh 读取携带（乐观锁 CAS），并检查影响行数
            po.setRowVersion(existing.getRowVersion());
            int updated = mapper.updateById(po);
            if (updated != 1) {
                throw new IllegalStateException("更新未影响一行（不存在/已删除/版本冲突）: id=" + existing.getId());
            }
        }
    }
}
