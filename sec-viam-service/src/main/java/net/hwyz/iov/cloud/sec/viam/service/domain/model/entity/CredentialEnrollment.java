package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 设备证书登记实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-002 / D-VIAM-004）
 * <p>
 * 迁入 VMD 证书申请/安装/补偿语义与 VmdVehicleCertificateService 目录职能；
 * PKI/CA 仍负责实际签发及吊销权威，FW-SEC 负责底层能力。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialEnrollment {

    /** 业务请求幂等键 */
    private String requestId;

    /** framework/PKI 返回的申请编号 */
    private String pkiRequestId;

    /** canonical 证书序列号（hex，DER 为权威来源） */
    private String certSn;

    /** 签发时车辆 VIN 快照 */
    private String vin;

    /** 签发时 active vehicle_part.id */
    private Long bindingId;

    /** 设备物理实例，关联 part_info.id */
    private Long partId;

    /** 设备类别 */
    private String deviceCategory;

    /** TBOX 物理实例序列号 */
    private String deviceSn;

    /** 签发时权威 HSM UID 快照 */
    private String hsmUid;

    /** 规范化 SubjectPublicKeyInfo SHA-256 */
    private String publicKeySha256;

    /** CSR 指纹 */
    private String csrFingerprint;

    /** 受治理逻辑证书 Profile */
    private String certificateProfile;

    /** 叶子证书 X.509 subject（RFC2253） */
    private String subject;

    /** 叶子证书 X.509 issuer（RFC2253） */
    private String issuer;

    /** 证书 SHA-256 指纹 */
    private String certificateFingerprint;

    /** SHA-256(原始 leaf DER)（Keyprov 冻结/ACK 绑定） */
    private byte[] leafCertificateDigest;

    /** 逻辑 Profile 签发后复验通过时间 */
    private Instant profileValidatedAt;

    /** 证书状态 */
    private CertificateState certStatus;

    /** 生效时间 */
    private Instant notBefore;

    /** 失效时间 */
    private Instant notAfter;

    /** 签发时间 */
    private Instant issuedAt;

    /** 安装确认时间 */
    private Instant confirmedAt;

    /** 非敏感失败原因 */
    private String failReason;

    /** 来源系统 */
    private String sourceSystem;

    /** MES 原请求号（人工补偿关联） */
    private String originalRequestId;

    /** 人工补偿原因 */
    private String compensationReason;

    /** 关联工单号 */
    private String ticketNo;

    /** 最后人工操作人 */
    private String lastOperator;

    /** 最后人工操作时间 */
    private Instant lastOperationAt;

    /** 产线设备号 */
    private String facilityNo;

    /** 产线工位代码 */
    private String lineCode;

    /** 证书状态 */
    public enum CertificateState {
        REQUESTED, ISSUING, ISSUED_NOT_CONFIRMED, ACTIVE, INSTALL_FAILED,
        FAILED, SUPERSEDED, REVOKED, EXPIRED, PENDING_RECONCILE
    }

    /**
     * 签发完成复验通过：ISSUED_NOT_CONFIRMED，登记证书元数据。
     */
    public void markIssued(String certSn, String fingerprint, String subject, String issuer,
                           Instant notBefore, Instant notAfter, byte[] leafDigest) {
        if (certStatus == CertificateState.FAILED || certStatus == CertificateState.REVOKED
                || certStatus == CertificateState.SUPERSEDED) {
            throw new IllegalStateException("终态不可回退为已签发: " + certStatus);
        }
        this.certSn = certSn;
        this.certificateFingerprint = fingerprint;
        this.subject = subject;
        this.issuer = issuer;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.leafCertificateDigest = leafDigest;
        this.profileValidatedAt = Instant.now();
        this.issuedAt = Instant.now();
        this.certStatus = CertificateState.ISSUED_NOT_CONFIRMED;
    }

    /**
     * 安装确认成功：作废同设备同 Profile 既有 ACTIVE 后激活（事务外保证由调用方执行）。
     */
    public void confirmInstalled() {
        if (certStatus != CertificateState.ISSUED_NOT_CONFIRMED
                && certStatus != CertificateState.INSTALL_FAILED) {
            throw new IllegalStateException("证书状态不允许确认安装: " + certStatus);
        }
        this.certStatus = CertificateState.ACTIVE;
        this.confirmedAt = Instant.now();
    }

    /**
     * 安装确认失败：INSTALL_FAILED。
     */
    public void confirmInstallFailed(String reason) {
        if (certStatus != CertificateState.ISSUED_NOT_CONFIRMED
                && certStatus != CertificateState.INSTALL_FAILED) {
            throw new IllegalStateException("证书状态不允许确认安装失败: " + certStatus);
        }
        this.certStatus = CertificateState.INSTALL_FAILED;
        this.failReason = reason;
    }

    /**
     * 确定性拒绝（签发后复验失败/PKI拒绝）：FAILED 终态；仅非终态可进入。
     */
    public void markFailed(String reason) {
        if (certStatus == CertificateState.ACTIVE || certStatus == CertificateState.SUPERSEDED
                || certStatus == CertificateState.REVOKED) {
            throw new IllegalStateException("终态不可回退为 FAILED: " + certStatus);
        }
        this.certStatus = CertificateState.FAILED;
        this.failReason = reason;
    }

    /**
     * 结果未知（PKI 请求已发送、响应丢失）：PENDING_RECONCILE，禁止自动重签。
     */
    public void markPendingReconcile(String reason) {
        this.certStatus = CertificateState.PENDING_RECONCILE;
        this.failReason = reason;
    }

    /**
     * 重新签发作废旧证：SUPERSEDED（仅已定案态可作废）。
     */
    public void supersedeForReissue() {
        if (certStatus != CertificateState.ISSUED_NOT_CONFIRMED
                && certStatus != CertificateState.ACTIVE
                && certStatus != CertificateState.INSTALL_FAILED
                && certStatus != CertificateState.EXPIRED) {
            throw new IllegalStateException("当前状态不允许重签作废: " + certStatus);
        }
        this.certStatus = CertificateState.SUPERSEDED;
    }

    /**
     * 是否可作为幂等复用的有效结果。
     */
    public boolean isReusableStatus() {
        return certStatus == CertificateState.REQUESTED
                || certStatus == CertificateState.ISSUING
                || certStatus == CertificateState.PENDING_RECONCILE
                || certStatus == CertificateState.ISSUED_NOT_CONFIRMED
                || certStatus == CertificateState.ACTIVE;
    }
}
