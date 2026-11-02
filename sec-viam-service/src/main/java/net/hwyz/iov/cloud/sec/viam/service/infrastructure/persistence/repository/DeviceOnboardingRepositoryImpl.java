package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.DeviceOnboardingConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.DeviceOnboardingMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DeviceOnboardingPo;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 安全开通状态仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class DeviceOnboardingRepositoryImpl implements DeviceOnboardingRepository {

    private final DeviceOnboardingMapper mapper;

    @Override
    public Optional<DeviceOnboarding> findByPrincipalId(String principalId) {
        return Optional.ofNullable(
                DeviceOnboardingConverter.toEntity(mapper.selectByPrincipalId(principalId)));
    }

    @Override
    public void save(DeviceOnboarding onboarding) {
        DeviceOnboardingPo po = DeviceOnboardingConverter.toPo(onboarding);
        DeviceOnboardingPo existing = mapper.selectByPrincipalId(onboarding.getPrincipalId());
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
