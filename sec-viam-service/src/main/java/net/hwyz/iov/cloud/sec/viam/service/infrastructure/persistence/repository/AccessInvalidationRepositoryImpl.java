package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationReason;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationType;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.AccessInvalidationRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.AccessInvalidationMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.AccessInvalidationPo;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 访问失效执行跟踪仓储实现（SEC-VIAM-DSN-CR-001 / G-3）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class AccessInvalidationRepositoryImpl implements AccessInvalidationRepository {

    private final AccessInvalidationMapper mapper;

    @Override
    public Optional<AccessInvalidationRecord> findByInvalidationId(String invalidationId) {
        return Optional.ofNullable(toEntity(mapper.selectByInvalidationId(invalidationId)));
    }

    @Override
    public List<AccessInvalidationRecord> listPendingBefore(Instant now, int limit) {
        return mapper.selectPendingBefore(toLdt(now), limit).stream()
                .map(this::toEntity).collect(Collectors.toList());
    }

    @Override
    public void save(AccessInvalidationRecord record) {
        AccessInvalidationPo existing = record.getId() == null
                ? mapper.selectByInvalidationId(record.getInvalidationId())
                : mapper.selectById(record.getId());
        AccessInvalidationPo po = toPo(record);
        if (existing == null) {
            mapper.insert(po);
            record.setId(po.getId());
        } else {
            po.setId(existing.getId());
            record.setId(existing.getId());
            // FW-MYSQL-DSN-CR-003：updatePo → updateById；原版本须由 fresh 读取携带（乐观锁 CAS），并检查影响行数
            po.setRowVersion(existing.getRowVersion());
            int updated = mapper.updateById(po);
            if (updated != 1) {
                throw new IllegalStateException("更新未影响一行（不存在/已删除/版本冲突）: id=" + existing.getId());
            }
        }
    }

    private AccessInvalidationPo toPo(AccessInvalidationRecord e) {
        return AccessInvalidationPo.builder()
                .id(e.getId())
                .invalidationId(e.getInvalidationId())
                .principalId(e.getPrincipalId())
                .hsmUid(e.getHsmUid())
                .vin(e.getVin())
                .deviceSn(e.getDeviceSn())
                .invalidationType(e.getInvalidationType() == null ? null : e.getInvalidationType().name())
                .reason(e.getReason() == null ? null : e.getReason().name())
                .scope(e.getScope())
                .securityVersion(e.getSecurityVersion())
                .bindingVersion(e.getBindingVersion())
                .targetGeneration(e.getTargetGeneration())
                .effectiveAt(toLdt(e.getEffectiveAt()))
                .effectiveBy(toLdt(e.getEffectiveBy()))
                .status(e.getStatus())
                .receiptState(e.getReceiptState())
                .receiptDetail(e.getReceiptDetail())
                .executionResultJson(e.getExecutionResultJson())
                .eventPayloadDigest(e.getEventPayloadDigest())
                .retryCount(e.getRetryCount())
                .lastRetryAt(toLdt(e.getLastRetryAt()))
                .timeoutAlerted(e.isTimeoutAlerted())
                .build();
    }

    private AccessInvalidationRecord toEntity(AccessInvalidationPo po) {
        if (po == null) {
            return null;
        }
        return AccessInvalidationRecord.builder()
                .id(po.getId())
                .invalidationId(po.getInvalidationId())
                .principalId(po.getPrincipalId())
                .hsmUid(po.getHsmUid())
                .vin(po.getVin())
                .deviceSn(po.getDeviceSn())
                .invalidationType(po.getInvalidationType() == null ? null
                        : AccessInvalidationType.valueOf(po.getInvalidationType()))
                .reason(po.getReason() == null ? null : AccessInvalidationReason.valueOf(po.getReason()))
                .scope(po.getScope())
                .securityVersion(po.getSecurityVersion() == null ? 0 : po.getSecurityVersion())
                .bindingVersion(po.getBindingVersion())
                .targetGeneration(po.getTargetGeneration())
                .effectiveAt(toInstant(po.getEffectiveAt()))
                .effectiveBy(toInstant(po.getEffectiveBy()))
                .status(po.getStatus())
                .receiptState(po.getReceiptState())
                .receiptDetail(po.getReceiptDetail())
                .executionResultJson(po.getExecutionResultJson())
                .eventPayloadDigest(po.getEventPayloadDigest())
                .retryCount(po.getRetryCount() == null ? 0 : po.getRetryCount())
                .lastRetryAt(toInstant(po.getLastRetryAt()))
                .timeoutAlerted(po.getTimeoutAlerted() != null && po.getTimeoutAlerted())
                .build();
    }

    private static LocalDateTime toLdt(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, java.time.ZoneId.systemDefault());
    }

    private static Instant toInstant(LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(java.time.ZoneId.systemDefault()).toInstant();
    }
}
