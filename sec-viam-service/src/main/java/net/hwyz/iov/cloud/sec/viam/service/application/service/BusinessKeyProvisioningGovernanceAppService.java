package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningClearBlockingVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * 业务密钥批次级治理应用服务（SEC-VIAM-DSN-CR-002 / FR-VIAM-003 / D-VIAM-018）
 * <p>
 * 唯一破坏性后台入口：服务端在事务内重做全部门禁，不依赖客户端「先查后写」判断。
 * 幂等键为 maintenanceRequestId，重复提交返回同一结果而不重复变更状态。
 * 清阻断只解除状态阻断，不重派生、不重包裹、不生成新版本。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BusinessKeyProvisioningGovernanceAppService {

    /** 批次级治理在通用审计表里的主体占位（该表 principal_id 非空，批次无主体） */
    static final String BATCH_AUDIT_PRINCIPAL = "KEYPROV_BATCH";

    private final ProvisioningBatchRepository batchRepository;
    private final SecurityOperationAuditRepository auditRepository;

    /**
     * 批次级一键清阻断（带期望状态/版本门禁与幂等）。
     *
     * @param requestId   批次 requestId
     * @param cmd         期望状态、期望修改时间、原因码/原因/工单
     * @param operatorId  服务端解析的操作人
     * @param operatorName 操作人姓名
     */
    @Transactional(rollbackFor = Exception.class)
    public ProvisioningOperationResultVo clearBlocking(String requestId, ProvisioningClearBlockingVo cmd,
                                                       String operatorId, String operatorName) {
        // 1) 幂等：同一 maintenanceRequestId 重复提交直接返回既有结果
        Optional<SecurityOperationAudit> existing = auditRepository.findByOperationId(cmd.getMaintenanceRequestId());
        if (existing.isPresent()) {
            SecurityOperationAudit audit = existing.get();
            log.info("批次清阻断幂等命中: requestId={}, maintenanceRequestId={}",
                    requestId, cmd.getMaintenanceRequestId());
            return ProvisioningOperationResultVo.builder()
                    .requestId(requestId)
                    .operationId(cmd.getMaintenanceRequestId())
                    .beforeStatus(parseDetail(audit.getDetail(), "before"))
                    .afterStatus(parseDetail(audit.getDetail(), "after"))
                    .result("IDEMPOTENT_HIT")
                    .occurredAt(audit.getOccurredAt())
                    .build();
        }

        // 2) 行锁读取，保证期望状态/版本判定与推进线性化
        ProvisioningBatch batch = batchRepository.findByRequestIdForUpdate(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));

        // 3) 终态不复活（先于期望状态比对，给出明确语义）
        ProvisioningBatch.BatchState state = batch.getStatus();
        if (state == ProvisioningBatch.BatchState.COMPLETED || state == ProvisioningBatch.BatchState.EXPIRED) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_TERMINAL_STATE_FROZEN);
        }
        if (state != ProvisioningBatch.BatchState.RECONCILE_REQUIRED
                && state != ProvisioningBatch.BatchState.FAILED) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_STATE_NOT_ALLOWED);
        }

        // 4) 期望状态与期望版本校验（并发变更即拒绝，不静默覆盖）
        if (!state.name().equals(cmd.getExpectedState())) {
            throw new ViamServiceException(ViamErrorCode.EXPECTED_STATE_MISMATCH,
                    "期望状态=" + cmd.getExpectedState() + "，当前状态=" + state.name());
        }
        if (batch.getModifyTime() == null
                || !batch.getModifyTime().equals(cmd.getExpectedModifyTime())) {
            throw new ViamServiceException(ViamErrorCode.EXPECTED_STATE_MISMATCH,
                    "期望修改时间与当前不一致（并发变更）");
        }

        // 5) 只解除状态阻断：RECONCILE_REQUIRED/FAILED → PREPARING，不重派生、不清零租约序号
        String beforeStatus = state.name();
        batch.setStatus(ProvisioningBatch.BatchState.PREPARING);
        batch.setFailReason(null);
        batch.setTerminalReason(null);
        batch.setTerminalAt(null);
        batchRepository.save(batch);

        // 6) 审计（与状态变更同事务）
        Instant now = Instant.now();
        SecurityOperationAudit audit = SecurityOperationAudit.builder()
                .operationId(cmd.getMaintenanceRequestId())
                .principalId(BATCH_AUDIT_PRINCIPAL)
                .deviceSn(batch.getDeviceSn())
                .operation("CLEAR_BLOCKING")
                .securityVersion(0L)
                .reason(truncate(cmd.getReason(), 128))
                .detail("before=" + beforeStatus + ";after=PREPARING;reasonCode=" + cmd.getReasonCode()
                        + ";ticketNo=" + cmd.getTicketNo() + ";batchRequestId=" + requestId)
                .operatorId(operatorId)
                .operatorName(operatorName)
                .callerType("MPT_ADMIN")
                .occurredAt(now)
                .build();
        auditRepository.save(audit);

        log.info("批次清阻断完成: requestId={}, {}→PREPARING, operator={}, reasonCode={}",
                requestId, beforeStatus, operatorId, cmd.getReasonCode());
        return ProvisioningOperationResultVo.builder()
                .requestId(requestId)
                .operationId(cmd.getMaintenanceRequestId())
                .beforeStatus(beforeStatus)
                .afterStatus(ProvisioningBatch.BatchState.PREPARING.name())
                .result("SUCCESS")
                .occurredAt(now)
                .build();
    }

    /**
     * 从 detail 中解析 {@code before=...;after=...} 片段（只用于幂等回放展示）。
     */
    static String parseDetail(String detail, String key) {
        if (detail == null || detail.isBlank()) {
            return null;
        }
        for (String part : detail.split(";")) {
            int idx = part.indexOf('=');
            if (idx > 0 && key.equals(part.substring(0, idx))) {
                return part.substring(idx + 1);
            }
        }
        return null;
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
