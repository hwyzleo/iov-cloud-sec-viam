package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 证书操作审计时间线项VO（SEC-VIAM-DSN-CR-002 / D-VIAM-013）
 * <p>
 * 只暴露脱敏字段：不含 CSR 全文、证书本体、请求摘要正文与来源 IP。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateOperationVo {

    /** 操作记录ID（幂等键） */
    private String operationId;

    /** 操作类型：COMPENSATE/RECONCILE/CONFIRM_INSTALLED/REISSUE/QUERY_CERTIFICATE */
    private String action;

    /** 操作人ID */
    private String operatorId;

    /** 操作人姓名 */
    private String operatorName;

    /** 人工原因 */
    private String reason;

    /** 关联工单号 */
    private String ticketNo;

    /** 操作前证书状态 */
    private String beforeStatus;

    /** 操作后证书状态 */
    private String afterStatus;

    /** 结果：SUCCESS/IDEMPOTENT_HIT/CONFLICT/FAILED/PENDING */
    private String result;

    /** 失败错误码（702xxx） */
    private String errorCode;

    /** 操作发生时间 */
    private Instant occurredAt;
}
