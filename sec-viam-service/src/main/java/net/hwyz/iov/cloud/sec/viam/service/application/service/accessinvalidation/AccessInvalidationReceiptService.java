package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.AccessInvalidationReceiptVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.AccessInvalidationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * 访问失效执行回执服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * VAGW 执行结果必须区分状态（CACHE_ACL_INVALIDATED/DISCONNECTED/SESSION_NOT_FOUND/
 * FAILED_RETRY/ACCEPTED）；仅"事件已消费"或"断连请求已提交"不得作为完成证据。
 * FAILED_RETRY 保持 PENDING 重试；SESSION_NOT_FOUND/DISCONNECTED/CACHE_ACL_INVALIDATED
 * 视为已执行（ACKNOWLEDGED）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessInvalidationReceiptService {

    private final AccessInvalidationRepository invalidationRepository;

    /**
     * 处理执行回执。
     *
     * @throws ViamServiceException 记录不存在/回执状态非法/重复冲突（fail-closed）
     */
    @Transactional(rollbackFor = Exception.class)
    public void handleReceipt(AccessInvalidationReceiptVo receipt) {
        if (receipt == null || receipt.getInvalidationId() == null || receipt.getReceiptState() == null) {
            throw new ViamServiceException(ViamErrorCode.ACCESS_INVALIDATION_RECEIPT_MISMATCH,
                    "回执字段缺失");
        }
        AccessInvalidationRecord record = invalidationRepository.findByInvalidationId(receipt.getInvalidationId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.ACCESS_INVALIDATION_NOT_FOUND,
                        "失效执行记录不存在: invalidationId=" + receipt.getInvalidationId()));
        if (AccessInvalidationRecord.STATUS_ACKNOWLEDGED.equals(record.getStatus())
                || AccessInvalidationRecord.STATUS_TIMEOUT.equals(record.getStatus())
                || AccessInvalidationRecord.STATUS_CANCELLED_STALE.equals(record.getStatus())) {
            throw new ViamServiceException(ViamErrorCode.ACCESS_INVALIDATION_RECEIPT_MISMATCH,
                    "执行记录已终态，拒绝重复回执: invalidationId=" + receipt.getInvalidationId());
        }
        switch (receipt.getReceiptState()) {
            case AccessInvalidationRecord.RECEIPT_CACHE_ACL_INVALIDATED,
                 AccessInvalidationRecord.RECEIPT_DISCONNECTED,
                 AccessInvalidationRecord.RECEIPT_SESSION_NOT_FOUND -> {
                record.setStatus(AccessInvalidationRecord.STATUS_ACKNOWLEDGED);
                record.setReceiptState(receipt.getReceiptState());
                record.setReceiptDetail(receipt.getDetail());
            }
            case AccessInvalidationRecord.RECEIPT_FAILED_RETRY -> {
                // 执行失败待重试：保持 PENDING，递增重试计数（由超时对账/调度继续观察）
                record.setReceiptState(receipt.getReceiptState());
                record.setReceiptDetail(receipt.getDetail());
                record.setRetryCount(record.getRetryCount() + 1);
                record.setLastRetryAt(Instant.now());
            }
            case AccessInvalidationRecord.RECEIPT_ACCEPTED -> {
                record.setReceiptState(receipt.getReceiptState());
                record.setReceiptDetail(receipt.getDetail());
            }
            default -> throw new ViamServiceException(ViamErrorCode.ACCESS_INVALIDATION_RECEIPT_MISMATCH,
                    "回执状态非法: " + receipt.getReceiptState());
        }
        invalidationRepository.save(record);
        log.info("访问失效执行回执: invalidationId={}, state={}, status={}",
                receipt.getInvalidationId(), receipt.getReceiptState(), record.getStatus());
    }
}
