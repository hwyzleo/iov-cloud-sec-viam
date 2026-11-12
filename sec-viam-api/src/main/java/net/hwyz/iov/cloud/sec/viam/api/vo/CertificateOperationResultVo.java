package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 证书人工操作结果VO（SEC-VIAM-DSN-CR-002 / D-VIAM-012 / D-VIAM-016）
 * <p>
 * 统一描述补偿/对账/补录/重签后的申请状态；证书本体经专用只读端点获取，不在此返回。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateOperationResultVo {

    /** 操作记录ID（幂等键） */
    private String operationId;

    /** 业务请求ID（重签为新的 requestId） */
    private String requestId;

    /** 操作类型 */
    private String action;

    /** 操作后证书状态 */
    private String status;

    /** 证书序列号（canonical hex） */
    private String certSn;

    /** PKI申请编号 */
    private String pkiRequestId;

    /** 证书颁发者 */
    private String issuer;

    /** 证书SHA-256指纹 */
    private String fingerprint;

    /** 生效时间 */
    private Instant notBefore;

    /** 失效时间 */
    private Instant notAfter;

    /** 失败原因（非敏感） */
    private String failReason;

    /** 操作结果：SUCCESS/IDEMPOTENT_HIT/PENDING */
    private String result;

    /** 操作发生时间 */
    private Instant occurredAt;
}
