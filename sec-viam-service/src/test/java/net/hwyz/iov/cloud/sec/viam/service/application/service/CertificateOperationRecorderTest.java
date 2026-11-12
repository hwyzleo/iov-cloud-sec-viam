package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CertificateOperationRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 证书操作审计记录器测试（SEC-VIAM-DSN-CR-002 / T10 / T11 / D-VIAM-013）。
 * <p>
 * 锁定：审计只存脱敏要素（CSR 仅以摘要参与）、operationId 唯一、幂等查询可用。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("SEC-VIAM-DSN-CR-002 证书操作审计")
class CertificateOperationRecorderTest {

    @Test
    @DisplayName("审计摘要只含 CSR 指纹，绝不含 CSR 全文")
    void requestDigestNeverContainsCsr() {
        InMemOperationRepo repo = new InMemOperationRepo();
        CertificateOperationRecorder recorder = new CertificateOperationRecorder(repo);

        CertificateOperation op = recorder.record(CertificateOperation.Action.COMPENSATE, "REQ-1",
                "100", "运维A", "MES未达", "T-1", "ORIG-1", null, "REQUESTED",
                CertificateOperation.Result.SUCCESS, null,
                "MIIC-this-is-the-whole-csr-body", "10.0.0.1", "JUnit");

        assertNotNull(op.getRequestDigest());
        assertEquals(64, op.getRequestDigest().length());
        assertFalse(op.getRequestDigest().contains("MIIC"));
        assertEquals("REQUESTED", op.getAfterStatus());
        assertEquals("T-1", op.getTicketNo());
    }

    @Test
    @DisplayName("相同入参两次记录产生不同 operationId（可追溯每一次人工动作）")
    void operationIdsAreUnique() throws InterruptedException {
        InMemOperationRepo repo = new InMemOperationRepo();
        CertificateOperationRecorder recorder = new CertificateOperationRecorder(repo);

        CertificateOperation first = recorder.record(CertificateOperation.Action.RECONCILE, "REQ-1",
                "100", null, null, null, null, "ISSUING", "ISSUING",
                CertificateOperation.Result.SUCCESS, null, null, null, null);
        Thread.sleep(2);
        CertificateOperation second = recorder.record(CertificateOperation.Action.RECONCILE, "REQ-1",
                "100", null, null, null, null, "ISSUING", "ISSUING",
                CertificateOperation.Result.SUCCESS, null, null, null, null);

        assertNotEquals(first.getOperationId(), second.getOperationId());
        assertEquals(2, repo.operations.size());
    }

    @Test
    @DisplayName("可按 operationId 幂等查询已记录的审计事实")
    void findByOperationIdReturnsRecordedFact() {
        InMemOperationRepo repo = new InMemOperationRepo();
        CertificateOperationRecorder recorder = new CertificateOperationRecorder(repo);
        CertificateOperation op = recorder.record(CertificateOperation.Action.QUERY_CERTIFICATE, "REQ-1",
                "100", null, null, null, null, "ACTIVE", "ACTIVE",
                CertificateOperation.Result.SUCCESS, null, null, null, null);

        Optional<CertificateOperation> found = recorder.findByOperationId(op.getOperationId());

        assertTrue(found.isPresent());
        assertEquals(CertificateOperation.Action.QUERY_CERTIFICATE, found.get().getAction());
    }

    static class InMemOperationRepo implements CertificateOperationRepository {
        final List<CertificateOperation> operations = new ArrayList<>();

        @Override
        public Optional<CertificateOperation> findByOperationId(String operationId) {
            return operations.stream().filter(o -> operationId.equals(o.getOperationId())).findFirst();
        }

        @Override
        public List<CertificateOperation> listByRequestId(String requestId) {
            return operations.stream().filter(o -> requestId.equals(o.getRequestId())).toList();
        }

        @Override
        public void save(CertificateOperation operation) {
            operations.add(operation);
        }
    }
}
