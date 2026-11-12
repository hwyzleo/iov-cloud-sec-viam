package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningClearBlockingVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 批次级清阻断测试（SEC-VIAM-DSN-CR-002 / T16 / D-VIAM-018）。
 * <p>
 * 锁定：期望状态/版本不一致即拒绝且无副作用、终态不复活、幂等键重复提交返回同一结果、
 * 审计与状态变更同事务落库。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("SEC-VIAM-DSN-CR-002 批次清阻断")
class BusinessKeyProvisioningGovernanceAppServiceTest {

    private InMemBatchRepo batchRepo;
    private InMemAuditRepo auditRepo;
    private BusinessKeyProvisioningGovernanceAppService service;
    private ProvisioningBatch batch;

    @BeforeEach
    void setUp() {
        batchRepo = new InMemBatchRepo();
        auditRepo = new InMemAuditRepo();
        service = new BusinessKeyProvisioningGovernanceAppService(batchRepo, auditRepo);
        batch = ProvisioningBatch.builder()
                .requestId("kp-1").deviceSn("SN-1").businessDomain("V2C_COMM")
                .status(ProvisioningBatch.BatchState.RECONCILE_REQUIRED)
                .failReason("PROVIDER_UNKNOWN")
                .modifyTime(Instant.parse("2026-11-12T10:00:00Z"))
                .rowVersion(3)
                .build();
        batch.setId(1L);
        batchRepo.save(batch);
    }

    @Test
    @DisplayName("T16 清阻断成功：RECONCILE_REQUIRED → PREPARING，并落 CLEAR_BLOCKING 审计")
    void clearBlockingSucceedsAndAudits() {
        ProvisioningOperationResultVo result = service.clearBlocking("kp-1", cmd("MR-1", "RECONCILE_REQUIRED",
                Instant.parse("2026-11-12T10:00:00Z")), "100", "运维A");

        assertEquals("SUCCESS", result.getResult());
        assertEquals("RECONCILE_REQUIRED", result.getBeforeStatus());
        assertEquals("PREPARING", result.getAfterStatus());
        assertEquals(ProvisioningBatch.BatchState.PREPARING, batch.getStatus());
        assertEquals(1, auditRepo.audits.size());
        SecurityOperationAudit audit = auditRepo.audits.get(0);
        assertEquals("CLEAR_BLOCKING", audit.getOperation());
        assertEquals("MR-1", audit.getOperationId());
        assertEquals("MPT_ADMIN", audit.getCallerType());
        assertTrue(audit.getDetail().contains("reasonCode=MANUAL_OPERATION"));
        assertTrue(audit.getDetail().contains("batchRequestId=kp-1"));
    }

    @Test
    @DisplayName("T16 幂等：同一 maintenanceRequestId 重复提交返回 IDEMPOTENT_HIT 且不重复变更")
    void clearBlockingIsIdempotent() {
        service.clearBlocking("kp-1", cmd("MR-2", "RECONCILE_REQUIRED",
                Instant.parse("2026-11-12T10:00:00Z")), "100", "运维A");
        // 状态已变为 PREPARING；再次提交同一 maintenanceRequestId 不得报错也不得重复推进
        ProvisioningOperationResultVo second = service.clearBlocking("kp-1", cmd("MR-2", "RECONCILE_REQUIRED",
                Instant.parse("2026-11-12T10:00:00Z")), "100", "运维A");

        assertEquals("IDEMPOTENT_HIT", second.getResult());
        assertEquals("RECONCILE_REQUIRED", second.getBeforeStatus());
        assertEquals("PREPARING", second.getAfterStatus());
        assertEquals(1, auditRepo.audits.size());
    }

    @Test
    @DisplayName("T16 期望状态不一致：返回 702222 且不产生副作用")
    void clearBlockingRejectsExpectedStateMismatch() {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.clearBlocking("kp-1", cmd("MR-3", "FAILED",
                        Instant.parse("2026-11-12T10:00:00Z")), "100", null));

        assertEquals(ViamErrorCode.EXPECTED_STATE_MISMATCH.getCode(), ex.getCode());
        assertEquals(ProvisioningBatch.BatchState.RECONCILE_REQUIRED, batch.getStatus());
        assertTrue(auditRepo.audits.isEmpty());
    }

    @Test
    @DisplayName("T16 期望修改时间不一致（并发变更）：返回 702222 且不产生副作用")
    void clearBlockingRejectsExpectedModifyTimeMismatch() {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.clearBlocking("kp-1", cmd("MR-4", "RECONCILE_REQUIRED",
                        Instant.parse("2026-11-12T09:00:00Z")), "100", null));

        assertEquals(ViamErrorCode.EXPECTED_STATE_MISMATCH.getCode(), ex.getCode());
        assertEquals(ProvisioningBatch.BatchState.RECONCILE_REQUIRED, batch.getStatus());
    }

    @Test
    @DisplayName("T16 终态不复活：COMPLETED 返回 702413")
    void clearBlockingRejectsCompletedBatch() {
        batch.setStatus(ProvisioningBatch.BatchState.COMPLETED);
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.clearBlocking("kp-1", cmd("MR-5", "COMPLETED",
                        Instant.parse("2026-11-12T10:00:00Z")), "100", null));

        assertEquals(ViamErrorCode.KEYPROV_TERMINAL_STATE_FROZEN.getCode(), ex.getCode());
        assertEquals(ProvisioningBatch.BatchState.COMPLETED, batch.getStatus());
    }

    @Test
    @DisplayName("T16 非阻塞态：WAIT_DEVICE_ACK 返回 702406")
    void clearBlockingRejectsNonBlockedBatch() {
        batch.setStatus(ProvisioningBatch.BatchState.WAIT_DEVICE_ACK);
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.clearBlocking("kp-1", cmd("MR-6", "WAIT_DEVICE_ACK",
                        Instant.parse("2026-11-12T10:00:00Z")), "100", null));

        assertEquals(ViamErrorCode.KEYPROV_PROVISIONING_STATE_NOT_ALLOWED.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T16 批次不存在：返回 702403")
    void clearBlockingRejectsUnknownBatch() {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.clearBlocking("kp-none", cmd("MR-7", "FAILED", Instant.now()), "100", null));
        assertEquals(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T16 审计 detail 解析：幂等回放可读回 before/after")
    void parseDetailReadsIdempotentReplay() {
        assertEquals("PREPARING",
                BusinessKeyProvisioningGovernanceAppService.parseDetail("before=FAILED;after=PREPARING", "after"));
        assertEquals("FAILED",
                BusinessKeyProvisioningGovernanceAppService.parseDetail("before=FAILED;after=PREPARING", "before"));
        assertEquals(null, BusinessKeyProvisioningGovernanceAppService.parseDetail(null, "before"));
        assertNotNull(BusinessKeyProvisioningGovernanceAppService.BATCH_AUDIT_PRINCIPAL);
    }

    private static ProvisioningClearBlockingVo cmd(String maintenanceRequestId, String expectedState,
                                                    Instant expectedModifyTime) {
        return ProvisioningClearBlockingVo.builder()
                .maintenanceRequestId(maintenanceRequestId)
                .expectedState(expectedState)
                .expectedModifyTime(expectedModifyTime)
                .reasonCode("MANUAL_OPERATION")
                .reason("ACK超时后人工复核清阻断")
                .ticketNo("T-100")
                .build();
    }

    static class InMemBatchRepo implements ProvisioningBatchRepository {
        final List<ProvisioningBatch> batches = new ArrayList<>();

        @Override
        public Optional<ProvisioningBatch> findByRequestId(String requestId) {
            return batches.stream().filter(b -> requestId.equals(b.getRequestId())).findFirst();
        }

        @Override
        public Optional<ProvisioningBatch> findOpenByDeviceSnAndDomain(String deviceSn, String businessDomain) {
            return batches.stream().filter(b -> deviceSn.equals(b.getDeviceSn())).findFirst();
        }

        @Override
        public List<ProvisioningBatch> listByDeviceSnAndDomain(String deviceSn, String businessDomain,
                                                               boolean includeTerminal, int limit) {
            return batches.stream().filter(b -> deviceSn.equals(b.getDeviceSn())).toList();
        }

        @Override
        public Optional<ProvisioningBatch> findByRequestIdForUpdate(String requestId) {
            return findByRequestId(requestId);
        }

        @Override
        public void save(ProvisioningBatch batch) {
            batches.removeIf(b -> b.getRequestId().equals(batch.getRequestId()));
            batches.add(batch);
        }

        @Override
        public void saveItem(ProvisioningItem item) {
        }

        @Override
        public List<ProvisioningItem> listItemsByProvisioningId(Long provisioningId) {
            return List.of();
        }
    }

    static class InMemAuditRepo implements SecurityOperationAuditRepository {
        final List<SecurityOperationAudit> audits = new ArrayList<>();

        @Override
        public Optional<SecurityOperationAudit> findByOperationId(String operationId) {
            return audits.stream().filter(a -> operationId.equals(a.getOperationId())).findFirst();
        }

        @Override
        public void save(SecurityOperationAudit audit) {
            audits.add(audit);
        }
    }
}
