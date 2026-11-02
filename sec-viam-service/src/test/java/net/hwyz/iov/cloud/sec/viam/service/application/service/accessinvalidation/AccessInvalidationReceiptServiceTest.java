package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationReason;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationType;
import net.hwyz.iov.cloud.sec.viam.api.vo.AccessInvalidationReceiptVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.AccessInvalidationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 访问失效执行回执服务测试（SEC-VIAM-DSN-CR-001 / G-3）
 * <p>
 * 回执区分状态；STALE_IGNORED（乱序旧事件被会话授权版本覆盖）→ CANCELLED_STALE；
 * 终态拒绝重复回执。
 * </p>
 *
 * @author hwyz_leo
 */
class AccessInvalidationReceiptServiceTest {

    private final InMemRepo repo = new InMemRepo();
    private AccessInvalidationReceiptService service;

    @BeforeEach
    void setUp() {
        service = new AccessInvalidationReceiptService(repo);
        repo.save(record("INV-1"));
    }

    private static AccessInvalidationRecord record(String id) {
        return AccessInvalidationRecord.builder()
                .invalidationId(id)
                .principalId("PR-1")
                .invalidationType(AccessInvalidationType.PRINCIPAL_REVOCATION)
                .reason(AccessInvalidationReason.BLOCK)
                .scope("PRINCIPAL")
                .securityVersion(10L)
                .effectiveAt(Instant.now())
                .effectiveBy(Instant.now().plusSeconds(30))
                .status(AccessInvalidationRecord.STATUS_PENDING)
                .build();
    }

    @Test
    void disconnectedReceiptAcknowledges() {
        service.handleReceipt(AccessInvalidationReceiptVo.builder()
                .invalidationId("INV-1").receiptState(AccessInvalidationRecord.RECEIPT_DISCONNECTED)
                .detail("kicked").build());
        assertEquals(AccessInvalidationRecord.STATUS_ACKNOWLEDGED, repo.byId.get("INV-1").getStatus());
        assertEquals(AccessInvalidationRecord.RECEIPT_DISCONNECTED, repo.byId.get("INV-1").getReceiptState());
    }

    @Test
    void staleIgnoredCancelsStale() {
        service.handleReceipt(AccessInvalidationReceiptVo.builder()
                .invalidationId("INV-1").receiptState(AccessInvalidationRecord.RECEIPT_STALE_IGNORED)
                .detail("session authorized after revocation").build());
        assertEquals(AccessInvalidationRecord.STATUS_CANCELLED_STALE, repo.byId.get("INV-1").getStatus());
        assertEquals(AccessInvalidationRecord.RECEIPT_STALE_IGNORED, repo.byId.get("INV-1").getReceiptState());
    }

    @Test
    void failedRetryKeepsPendingAndIncrements() {
        service.handleReceipt(AccessInvalidationReceiptVo.builder()
                .invalidationId("INV-1").receiptState(AccessInvalidationRecord.RECEIPT_FAILED_RETRY)
                .detail("kick api timeout").build());
        assertEquals(AccessInvalidationRecord.STATUS_PENDING, repo.byId.get("INV-1").getStatus());
        assertEquals(1, repo.byId.get("INV-1").getRetryCount());
    }

    @Test
    void terminalRejectsDuplicateReceipt() {
        service.handleReceipt(AccessInvalidationReceiptVo.builder()
                .invalidationId("INV-1").receiptState(AccessInvalidationRecord.RECEIPT_DISCONNECTED).build());
        assertThrows(ViamServiceException.class, () -> service.handleReceipt(
                AccessInvalidationReceiptVo.builder()
                        .invalidationId("INV-1").receiptState(AccessInvalidationRecord.RECEIPT_DISCONNECTED).build()));
    }

    static class InMemRepo implements AccessInvalidationRepository {
        final Map<String, AccessInvalidationRecord> byId = new HashMap<>();

        @Override
        public Optional<AccessInvalidationRecord> findByInvalidationId(String invalidationId) {
            return byId.values().stream()
                    .filter(r -> invalidationId.equals(r.getInvalidationId())).findFirst();
        }

        @Override
        public List<AccessInvalidationRecord> listPendingBefore(Instant now, int limit) {
            return List.of();
        }

        @Override
        public void save(AccessInvalidationRecord record) {
            byId.put(record.getInvalidationId(), record);
        }
    }
}
