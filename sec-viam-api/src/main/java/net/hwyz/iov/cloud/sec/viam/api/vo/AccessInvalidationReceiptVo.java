package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 访问失效执行回执（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * VAGW 执行结果区分状态：CACHE_ACL_INVALIDATED / DISCONNECTED / SESSION_NOT_FOUND /
 * FAILED_RETRY / ACCEPTED；不能仅以"事件已消费"或"断连请求已提交"作为完成证据。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessInvalidationReceiptVo {

    /** 失效请求ID（事件幂等键） */
    private String invalidationId;

    /** 回执状态（CACHE_ACL_INVALIDATED/DISCONNECTED/SESSION_NOT_FOUND/FAILED_RETRY/ACCEPTED） */
    private String receiptState;

    /** 执行明细（非敏感；VAGW 执行证据摘要） */
    private String detail;

    /** VAGW 执行时间 */
    private java.time.Instant executedAt;
}
