package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.SecurityOperationAuditMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityOperationAuditPo;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * 安全操作审计仓储实现（SEC-VIAM-DSN-CR-001 / T05）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class SecurityOperationAuditRepositoryImpl implements SecurityOperationAuditRepository {

    private final SecurityOperationAuditMapper mapper;

    @Override
    public Optional<SecurityOperationAudit> findByOperationId(String operationId) {
        return Optional.ofNullable(toEntity(mapper.selectByOperationId(operationId)));
    }

    @Override
    public void save(SecurityOperationAudit audit) {
        SecurityOperationAuditPo existing = audit.getId() == null
                ? mapper.selectByOperationId(audit.getOperationId())
                : mapper.selectPoById(audit.getId());
        SecurityOperationAuditPo po = toPo(audit);
        if (existing == null) {
            mapper.insertPo(po);
            audit.setId(po.getId());
        } else {
            po.setId(existing.getId());
            audit.setId(existing.getId());
            mapper.updatePo(po);
        }
    }

    private SecurityOperationAuditPo toPo(SecurityOperationAudit e) {
        return SecurityOperationAuditPo.builder()
                .id(e.getId())
                .operationId(e.getOperationId())
                .principalId(e.getPrincipalId())
                .hsmUid(e.getHsmUid())
                .vin(e.getVin())
                .deviceSn(e.getDeviceSn())
                .operation(e.getOperation())
                .securityVersion(e.getSecurityVersion())
                .reason(e.getReason())
                .detail(e.getDetail())
                .operatorId(e.getOperatorId())
                .operatorName(e.getOperatorName())
                .callerType(e.getCallerType())
                .occurredAt(toLdt(e.getOccurredAt()))
                .build();
    }

    private SecurityOperationAudit toEntity(SecurityOperationAuditPo po) {
        if (po == null) {
            return null;
        }
        return SecurityOperationAudit.builder()
                .id(po.getId())
                .operationId(po.getOperationId())
                .principalId(po.getPrincipalId())
                .hsmUid(po.getHsmUid())
                .vin(po.getVin())
                .deviceSn(po.getDeviceSn())
                .operation(po.getOperation())
                .securityVersion(po.getSecurityVersion() == null ? 0 : po.getSecurityVersion())
                .reason(po.getReason())
                .detail(po.getDetail())
                .operatorId(po.getOperatorId())
                .operatorName(po.getOperatorName())
                .callerType(po.getCallerType())
                .occurredAt(toInstant(po.getOccurredAt()))
                .build();
    }

    private static LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, java.time.ZoneId.systemDefault());
    }

    private static java.time.Instant toInstant(LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(java.time.ZoneId.systemDefault()).toInstant();
    }
}
