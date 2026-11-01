package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
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
        PrincipalAssetMappingPo po = mapper.selectPoByMap(java.util.Map.of(
                "principal_id", principalId, "vin", vin, "status", "ACTIVE", "row_valid", 1))
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
            mapper.insertPo(po);
        } else {
            po.setId(existing.getId());
            mapper.updatePo(po);
        }
    }
}
