package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 证书人工操作审计实体（SEC-VIAM-DSN-CR-002 / FR-VIAM-007 / D-VIAM-013）
 * <p>
 * 不可篡改的操作事实：补偿/对账/安装补录/重签/证书本体重取。
 * 只保存脱敏要素（原因、工单、操作前后状态、结果、错误码），
 * 不保存 CSR 全文、证书本体与密钥材料；requestDigest 仅存规范化摘要+CSR指纹。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateOperation {

    /** 主键（DB 自增） */
    private Long id;

    /** 操作记录ID（幂等键） */
    private String operationId;

    /** 关联证书申请 request_id */
    private String requestId;

    /** 操作类型 */
    private Action action;

    /** 操作人ID（服务端解析，禁止自报） */
    private String operatorId;

    /** 操作人姓名 */
    private String operatorName;

    /** 人工原因 */
    private String reason;

    /** 关联工单号 */
    private String ticketNo;

    /** MES原请求号 */
    private String originalRequestId;

    /** 操作前证书状态 */
    private String beforeStatus;

    /** 操作后证书状态 */
    private String afterStatus;

    /** 规范化请求摘要 + CSR指纹（不含 CSR 全文/证书本体） */
    private String requestDigest;

    /** 操作结果 */
    private Result result;

    /** 失败错误码（702xxx） */
    private String errorCode;

    /** 来源IP */
    private String sourceIp;

    /** 终端User-Agent */
    private String userAgent;

    /** 操作发生时间 */
    private Instant occurredAt;

    /**
     * 操作类型。
     */
    public enum Action {
        COMPENSATE, RECONCILE, CONFIRM_INSTALLED, REISSUE, QUERY_CERTIFICATE
    }

    /**
     * 操作结果。
     */
    public enum Result {
        SUCCESS, IDEMPOTENT_HIT, CONFLICT, FAILED, PENDING
    }
}
