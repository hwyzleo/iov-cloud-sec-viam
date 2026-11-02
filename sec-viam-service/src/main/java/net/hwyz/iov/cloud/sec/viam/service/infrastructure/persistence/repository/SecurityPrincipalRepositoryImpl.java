package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.SecurityPrincipalConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.SecurityPrincipalMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityPrincipalPo;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 安全主体仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class SecurityPrincipalRepositoryImpl implements SecurityPrincipalRepository {

    private final SecurityPrincipalMapper mapper;

    @Override
    public Optional<SecurityPrincipal> findByPrincipalId(String principalId) {
        return Optional.ofNullable(SecurityPrincipalConverter.toEntity(mapper.selectByPrincipalId(principalId)));
    }

    @Override
    public Optional<SecurityPrincipal> findByHsmUid(String hsmUid) {
        return Optional.ofNullable(SecurityPrincipalConverter.toEntity(mapper.selectByHsmUid(hsmUid)));
    }

    @Override
    public void save(SecurityPrincipal principal) {
        SecurityPrincipalPo po = SecurityPrincipalConverter.toPo(principal);
        SecurityPrincipalPo existing = mapper.selectByPrincipalId(principal.getPrincipalId());
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
    public List<SecurityPrincipal> listAll(int offset, int limit) {
        // FW-MYSQL-DSN-CR-003：selectPoByMap → LambdaQueryWrapper；row_valid=1 由 @TableLogic 自动过滤，
        // offset/limit 与旧路径一致未参与查询（保留契约）
        return mapper.selectList(Wrappers.<SecurityPrincipalPo>lambdaQuery()).stream()
                .map(SecurityPrincipalConverter::toEntity).collect(Collectors.toList());
    }
}
