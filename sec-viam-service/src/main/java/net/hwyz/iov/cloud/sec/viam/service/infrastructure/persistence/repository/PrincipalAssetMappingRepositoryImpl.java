package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.PrincipalAssetMappingConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.PrincipalAssetMappingMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.PrincipalAssetMappingPo;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 安全主体资产映射仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class PrincipalAssetMappingRepositoryImpl implements PrincipalAssetMappingRepository {

    private final PrincipalAssetMappingMapper mapper;

    @Override
    public Optional<PrincipalAssetMapping> findByPrincipalAndVin(String principalId, String vin) {
        // FW-MYSQL-DSN-CR-003：selectPoByMap → LambdaQueryWrapper；保留原条件（principalId/vin/status=ACTIVE），
        // row_valid=1 由 @TableLogic 自动过滤
        PrincipalAssetMappingPo po = mapper.selectList(Wrappers.<PrincipalAssetMappingPo>lambdaQuery()
                        .eq(PrincipalAssetMappingPo::getPrincipalId, principalId)
                        .eq(PrincipalAssetMappingPo::getVin, vin)
                        .eq(PrincipalAssetMappingPo::getStatus, "ACTIVE"))
                .stream().findFirst().orElse(null);
        return Optional.ofNullable(PrincipalAssetMappingConverter.toEntity(po));
    }

    @Override
    public List<PrincipalAssetMapping> listActiveByPrincipalId(String principalId) {
        return mapper.selectActiveByPrincipalId(principalId).stream()
                .map(PrincipalAssetMappingConverter::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public List<PrincipalAssetMapping> listActiveByVin(String vin) {
        return mapper.selectActiveByVin(vin).stream()
                .map(PrincipalAssetMappingConverter::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public Optional<PrincipalAssetMapping> findActiveByDeviceSn(String deviceSn) {
        return Optional.ofNullable(
                PrincipalAssetMappingConverter.toEntity(mapper.selectActiveByDeviceSn(deviceSn)));
    }

    @Override
    public void save(PrincipalAssetMapping mapping) {
        PrincipalAssetMappingPo po = PrincipalAssetMappingConverter.toPo(mapping);
        PrincipalAssetMappingPo existing = mapper.selectActiveByDeviceSn(mapping.getDeviceSn());
        if (existing == null || !existing.getVin().equals(mapping.getVin())) {
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
