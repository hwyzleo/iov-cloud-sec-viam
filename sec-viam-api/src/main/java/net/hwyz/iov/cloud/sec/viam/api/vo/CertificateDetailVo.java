package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * 证书申请详情VO（SEC-VIAM-DSN-CR-002 / FR-VIAM-002 / D-VIAM-013）
 * <p>
 * 详情只返回 CSR SHA-256 指纹，不返回 CSR 全文与证书本体；附带脱敏操作审计时间线。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateDetailVo {

    /** 业务请求ID */
    private String requestId;

    /** MES原请求号 */
    private String originalRequestId;

    /** PKI申请编号 */
    private String pkiRequestId;

    /** 车辆VIN */
    private String vin;

    /** 设备类别 */
    private String deviceCategory;

    /** 设备SN */
    private String deviceSn;

    /** 证书Profile */
    private String certificateProfile;

    /** CSR SHA-256 指纹（不含 CSR 全文） */
    private String csrFingerprint;

    /** X.509 Subject（RFC2253） */
    private String subject;

    /** X.509 Issuer（RFC2253） */
    private String issuer;

    /** 证书序列号（canonical hex） */
    private String certSn;

    /** 证书状态 */
    private String status;

    /** 来源系统 */
    private String sourceSystem;

    /** 证书SHA-256指纹 */
    private String certificateFingerprint;

    /** 有效期开始 */
    private Instant notBefore;

    /** 有效期结束 */
    private Instant notAfter;

    /** 签发时间 */
    private Instant issuedAt;

    /** 安装确认时间 */
    private Instant confirmedAt;

    /** 人工补偿原因 */
    private String compensationReason;

    /** 关联工单号 */
    private String ticketNo;

    /** 最后人工操作人 */
    private String lastOperator;

    /** 最后人工操作时间 */
    private Instant lastOperationAt;

    /** 最近失败原因（非敏感） */
    private String failReason;

    /** 创建时间 */
    private Instant createTime;

    /** 修改时间 */
    private Instant modifyTime;

    /** 脱敏操作审计时间线（按发生时间升序） */
    private List<CertificateOperationVo> operations;
}
