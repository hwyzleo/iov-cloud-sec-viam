package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;

import java.util.Optional;

/**
 * 准入裁决审计仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-005 / D-VIAM-007）
 *
 * @author hwyz_leo
 */
public interface DecisionAuditRepository {

    /**
     * 按准入裁决ID查询。
     */
    Optional<DecisionAudit> findByAdmissionDecisionId(String admissionDecisionId);

    /**
     * 保存。
     */
    void save(DecisionAudit audit);
}
