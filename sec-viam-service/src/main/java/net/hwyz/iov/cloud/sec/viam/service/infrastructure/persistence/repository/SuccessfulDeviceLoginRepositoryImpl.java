package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SuccessfulDeviceLoginRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.SuccessfulDeviceLoginConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.SuccessfulDeviceLoginMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SuccessfulDeviceLoginPo;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

/**
 * 成功接入记录仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class SuccessfulDeviceLoginRepositoryImpl implements SuccessfulDeviceLoginRepository {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private final SuccessfulDeviceLoginMapper mapper;

    @Override
    public Optional<SuccessfulDeviceLogin> findByLoginId(String loginId) {
        return Optional.ofNullable(
                SuccessfulDeviceLoginConverter.toEntity(mapper.selectByLoginId(loginId)));
    }

    @Override
    public void save(SuccessfulDeviceLogin login) {
        SuccessfulDeviceLoginPo po = SuccessfulDeviceLoginConverter.toPo(login);
        SuccessfulDeviceLoginPo existing = mapper.selectByLoginId(login.getLoginId());
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

    @Override
    public Optional<Instant> findFirstLoginTime(String principalId) {
        java.time.LocalDateTime ldt = mapper.selectFirstLoginTime(principalId);
        return Optional.ofNullable(ldt).map(t -> t.atZone(UTC).toInstant());
    }

    @Override
    public Optional<Instant> findLastLoginTime(String principalId) {
        java.time.LocalDateTime ldt = mapper.selectLastLoginTime(principalId);
        return Optional.ofNullable(ldt).map(t -> t.atZone(UTC).toInstant());
    }
}
