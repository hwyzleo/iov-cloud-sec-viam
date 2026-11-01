package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * KL1 开通批次状态机单元测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / T04）
 * <p>
 * 覆盖：F 不可滑动、B 固定截止、终态不复活、完整用途集 ACK 后原子激活、结果未知转对账。
 * </p>
 *
 * @author hwyz_leo
 */
class ProvisioningBatchTest {

    private ProvisioningBatch newBatch() {
        return ProvisioningBatch.builder()
                .requestId("REQ-001")
                .deviceSn("SN-0001")
                .businessDomain("V2C_COMM")
                .status(ProvisioningBatch.BatchState.PREPARING)
                .build();
    }

    @Test
    void freezeFirstIssuance_fixedOnce() {
        ProvisioningBatch batch = newBatch();
        batch.freezeFirstIssuance(new byte[]{1, 2, 3}, "digest", 300);
        assertEquals(ProvisioningBatch.BatchState.WAIT_DEVICE_ACK, batch.getStatus());
        assertEquals("KEYPROV-LIFECYCLE-1", batch.getLifecycleProfile());
        assertThrows(IllegalStateException.class,
                () -> batch.freezeFirstIssuance(new byte[]{4, 5}, "digest2", 300));
    }

    @Test
    void acknowledge_rejectsLateAckBeyondDeadline() {
        ProvisioningBatch batch = newBatch();
        Instant f = Instant.parse("2026-11-01T10:00:00Z");
        batch.freezeFirstIssuance(new byte[]{1}, "digest", 300);
        // 直接模拟 F 时间后 301s 的 ACK
        Instant late = f.plusSeconds(301);
        // ackDeadlineAt 由 freezeFirstIssuance 以 now 计算，这里验证超时判定逻辑：
        assertThrows(IllegalStateException.class,
                () -> batch.acknowledge("ack", Instant.parse("2030-01-01T00:00:00Z"), true));
    }

    @Test
    void acknowledge_incompletePurposeSetRejected() {
        ProvisioningBatch batch = newBatch();
        batch.freezeFirstIssuance(new byte[]{1}, "digest", 300);
        assertThrows(IllegalStateException.class,
                () -> batch.acknowledge("ack", Instant.now(), false));
    }

    @Test
    void acknowledge_completesAndTerminalNotRevived() {
        ProvisioningBatch batch = newBatch();
        batch.freezeFirstIssuance(new byte[]{1}, "digest", 300);
        batch.acknowledge("ackDigest", Instant.now(), true);
        assertEquals(ProvisioningBatch.BatchState.COMPLETED, batch.getStatus());
        assertThrows(IllegalStateException.class,
                () -> batch.acknowledge("ack2", Instant.now(), true));
        assertThrows(IllegalStateException.class,
                () -> batch.markReconcileRequired("replay"));
    }

    @Test
    void expireByAckTimeout_marksTerminal() {
        ProvisioningBatch batch = newBatch();
        batch.freezeFirstIssuance(new byte[]{1}, "digest", 300);
        batch.expireByAckTimeout(Instant.now());
        assertEquals(ProvisioningBatch.BatchState.EXPIRED, batch.getStatus());
        assertEquals("ACK_TIMEOUT", batch.getTerminalReason());
        assertThrows(IllegalStateException.class,
                () -> batch.acknowledge("ack", Instant.now(), true));
    }

    @Test
    void markReconcileRequired_unknownOutcomeNoAutoReplay() {
        ProvisioningBatch batch = newBatch();
        batch.markReconcileRequired("PKI结果未知");
        assertEquals(ProvisioningBatch.BatchState.RECONCILE_REQUIRED, batch.getStatus());
    }
}
