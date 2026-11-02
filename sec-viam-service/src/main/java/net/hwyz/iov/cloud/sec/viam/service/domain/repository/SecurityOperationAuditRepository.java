package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;

import java.util.Optional;

/**
 * 安全操作审计仓储（SEC-VIAM-DSN-CR-001 / T05）
 *
 * @author hwyz_leo
 */
public interface SecurityOperationAuditRepository {

    Optional<SecurityOperationAudit> findByOperationId(String operationId);

    void save(SecurityOperationAudit audit);
}
