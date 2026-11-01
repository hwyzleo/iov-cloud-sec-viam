package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DecisionAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.DecisionAuditConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.DecisionAuditMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DecisionAuditPo;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 准入裁决审计仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class DecisionAuditRepositoryImpl implements DecisionAuditRepository {

    private final DecisionAuditMapper mapper;

    @Override
    public Optional<DecisionAudit> findByAdmissionDecisionId(String admissionDecisionId) {
        return Optional.ofNullable(
                DecisionAuditConverter.toEntity(mapper.selectByAdmissionDecisionId(admissionDecisionId)));
    }

    @Override
    public void save(DecisionAudit audit) {
        DecisionAuditPo po = DecisionAuditConverter.toPo(audit);
        DecisionAuditPo existing = mapper.selectByAdmissionDecisionId(audit.getAdmissionDecisionId());
        if (existing == null) {
            mapper.insertPo(po);
        } else {
            po.setId(existing.getId());
            mapper.updatePo(po);
        }
    }
}
