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
