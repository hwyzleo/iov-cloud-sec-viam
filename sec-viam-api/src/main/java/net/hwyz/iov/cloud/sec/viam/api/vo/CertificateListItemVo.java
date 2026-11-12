package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 证书申请列表项VO（SEC-VIAM-DSN-CR-002 / FR-VIAM-002 / D-VIAM-011）
 * <p>
 * 列表不返回 CSR 全文、CSR 原文、证书本体与任何密钥材料；行标识为 requestId。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateListItemVo {

    /** 业务请求ID（行标识） */
    private String requestId;

    /** MES原请求号 */
    private String originalRequestId;

    /** 车辆VIN */
    private String vin;

    /** 设备类别 */
    private String deviceCategory;

    /** 设备SN */
    private String deviceSn;

    /** 证书Profile */
    private String certificateProfile;

    /** 证书序列号（canonical hex） */
    private String certSn;

    /** 证书状态 */
    private String status;

    /** 来源系统（MES / MPT_COMPENSATION） */
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

    /** 最后人工操作人 */
    private String lastOperator;

    /** 最后人工操作时间 */
    private Instant lastOperationAt;

    /** 最近失败原因（非敏感） */
    private String failReason;

    /** 修改时间 */
    private Instant modifyTime;
}
