package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import net.hwyz.iov.cloud.framework.mysql.po.BasePo;

import java.time.LocalDateTime;

/**
 * 设备证书登记表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_credential_enrollment")
public class CredentialEnrollmentPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("request_id")
    private String requestId;

    @TableField("pki_request_id")
    private String pkiRequestId;

    @TableField("cert_sn")
    private String certSn;

    @TableField("vin")
    private String vin;

    @TableField("binding_id")
    private Long bindingId;

    @TableField("part_id")
    private Long partId;

    @TableField("device_category")
    private String deviceCategory;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("public_key_sha256")
    private String publicKeySha256;

    @TableField("csr_fingerprint")
    private String csrFingerprint;

    @TableField("certificate_profile")
    private String certificateProfile;

    @TableField("subject")
    private String subject;

    @TableField("issuer")
    private String issuer;

    @TableField("certificate_fingerprint")
    private String certificateFingerprint;

    @TableField("leaf_certificate_digest")
    private byte[] leafCertificateDigest;

    @TableField("profile_validated_at")
    private LocalDateTime profileValidatedAt;

    @TableField("cert_status")
    private String certStatus;

    @TableField("not_before")
    private LocalDateTime notBefore;

    @TableField("not_after")
    private LocalDateTime notAfter;

    @TableField("issued_at")
    private LocalDateTime issuedAt;

    @TableField("confirmed_at")
    private LocalDateTime confirmedAt;

    @TableField("fail_reason")
    private String failReason;

    @TableField("source_system")
    private String sourceSystem;

    @TableField("original_request_id")
    private String originalRequestId;

    @TableField("compensation_reason")
    private String compensationReason;

    @TableField("ticket_no")
    private String ticketNo;

    @TableField("last_operator")
    private String lastOperator;

    @TableField("last_operation_at")
    private LocalDateTime lastOperationAt;

    @TableField("facility_no")
    private String facilityNo;

    @TableField("line_code")
    private String lineCode;
}
