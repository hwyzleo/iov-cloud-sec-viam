package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 设备证书状态VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateStatusVo {

    /** 业务请求ID */
    private String requestId;

    /** 状态 */
    private String status;

    /** 证书序列号（canonical hex） */
    private String certSn;

    /** 证书指纹 */
    private String certificateFingerprint;

    /** 证书颁发者 */
    private String issuer;

    /** 生效时间 */
    private Instant notBefore;

    /** 失效时间 */
    private Instant notAfter;

    /** 签发时间 */
    private Instant issuedAt;

    /** 安装确认时间 */
    private Instant confirmedAt;

    /** 失败原因（非敏感） */
    private String failReason;

    /** 证书DER Base64编码（重取回填，可空） */
    private String certificateDerBase64;

    /** 证书链DER Base64编码（可空） */
    private String[] chainDerBase64;
}
