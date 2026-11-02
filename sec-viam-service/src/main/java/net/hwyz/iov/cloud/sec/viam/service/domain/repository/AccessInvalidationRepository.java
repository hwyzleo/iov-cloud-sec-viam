package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 访问失效执行跟踪仓储（SEC-VIAM-DSN-CR-001 / G-3）
 *
 * @author hwyz_leo
 */
public interface AccessInvalidationRepository {

    Optional<AccessInvalidationRecord> findByInvalidationId(String invalidationId);

    List<AccessInvalidationRecord> listPendingBefore(Instant now, int limit);

    void save(AccessInvalidationRecord record);
}
