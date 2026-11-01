package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
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
            mapper.insertPo(po);
        } else {
            po.setId(existing.getId());
            mapper.updatePo(po);
        }
    }

    @Override
    public List<SecurityPrincipal> listAll(int offset, int limit) {
        return mapper.selectPoByMap(java.util.Map.of("row_valid", 1)).stream()
                .map(SecurityPrincipalConverter::toEntity).collect(Collectors.toList());
    }
}
