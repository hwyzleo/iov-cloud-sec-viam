package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.KeyProvisioningLease;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.KeyProvisioningLeaseRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.KeyProvisioningLeaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.KeyProvisioningLeasePo;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * KL1 交付租约仓储实现（SEC-VIAM-DSN-CR-001 / G-2）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class KeyProvisioningLeaseRepositoryImpl implements KeyProvisioningLeaseRepository {

    private final KeyProvisioningLeaseMapper mapper;

    @Override
    public Optional<KeyProvisioningLease> findByProvisioningAndSeq(Long provisioningId, int leaseSeq) {
        return Optional.ofNullable(toEntity(
                mapper.selectByProvisioningAndSeq(provisioningId, leaseSeq)));
    }

    @Override
    public Optional<KeyProvisioningLease> findByMessageId(String messageId) {
        return Optional.ofNullable(toEntity(mapper.selectByMessageId(messageId)));
    }

    @Override
    public void save(KeyProvisioningLease lease) {
        KeyProvisioningLeasePo existing = lease.getId() == null
                ? mapper.selectByProvisioningAndSeq(lease.getProvisioningId(), lease.getLeaseSeq())
                : mapper.selectPoById(lease.getId());
        KeyProvisioningLeasePo po = toPo(lease);
        if (existing == null) {
            mapper.insertPo(po);
            lease.setId(po.getId());
        } else {
            po.setId(existing.getId());
            lease.setId(existing.getId());
            mapper.updatePo(po);
        }
    }

    private static KeyProvisioningLeasePo toPo(KeyProvisioningLease e) {
        return KeyProvisioningLeasePo.builder()
                .id(e.getId())
                .provisioningId(e.getProvisioningId())
                .leaseSeq(e.getLeaseSeq())
                .issuedAt(toLdt(e.getIssuedAt()))
                .expireAt(toLdt(e.getExpireAt()))
                .messageId(e.getMessageId())
                .correlationId(e.getCorrelationId())
                .deliveryPayloadDigest(e.getDeliveryPayloadDigest())
                .contentDigest(e.getContentDigest())
                .payload(e.getPayload())
                .payloadRef(e.getPayloadRef())
                .build();
    }

    private static KeyProvisioningLease toEntity(KeyProvisioningLeasePo po) {
        if (po == null) {
            return null;
        }
        return KeyProvisioningLease.builder()
                .id(po.getId())
                .provisioningId(po.getProvisioningId())
                .leaseSeq(po.getLeaseSeq() == null ? 0 : po.getLeaseSeq())
                .issuedAt(toInstant(po.getIssuedAt()))
                .expireAt(toInstant(po.getExpireAt()))
                .messageId(po.getMessageId())
                .correlationId(po.getCorrelationId())
                .deliveryPayloadDigest(po.getDeliveryPayloadDigest())
                .contentDigest(po.getContentDigest())
                .payload(po.getPayload())
                .payloadRef(po.getPayloadRef())
                .build();
    }

    private static LocalDateTime toLdt(java.time.Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, java.time.ZoneId.systemDefault());
    }

    private static java.time.Instant toInstant(LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(java.time.ZoneId.systemDefault()).toInstant();
    }
}
