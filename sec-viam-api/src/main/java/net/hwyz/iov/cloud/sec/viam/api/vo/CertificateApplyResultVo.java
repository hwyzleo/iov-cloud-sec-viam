package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 设备证书申请结果VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 * <p>
 * 证书本体不落库；优先同步签发回传，缺失时经 pki_request_id 重取回填。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateApplyResultVo {

    /** 业务请求ID */
    private String requestId;

    /** 状态（REQUESTED/ISSUING/ISSUED_NOT_CONFIRMED/ACTIVE/FAILED/PENDING_RECONCILE 等） */
    private String status;

    /** 证书序列号（canonical hex） */
    private String certSn;

    /** PKI申请编号 */
    private String pkiRequestId;

    /** 证书DER Base64编码 */
    private String certificateDerBase64;

    /** 证书链DER Base64编码 */
    private String[] chainDerBase64;

    /** 证书颁发者 */
    private String issuer;

    /** 证书指纹 */
    private String fingerprint;

    /** 生效时间 */
    private String notBefore;

    /** 失效时间 */
    private String notAfter;

    /** 失败原因（非敏感） */
    private String failReason;
}
