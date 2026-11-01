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
 * 设备业务密钥目录表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_device_business_key")
public class DeviceBusinessKeyPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("binding_id")
    private Long bindingId;

    @TableField("part_id")
    private Long partId;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("business_domain")
    private String businessDomain;

    @TableField("purpose")
    private String purpose;

    @TableField("material_model")
    private String materialModel;

    @TableField("key_id")
    private String keyId;

    @TableField("business_key_version")
    private long businessKeyVersion;

    @TableField("kms_key_ref")
    private String kmsKeyRef;

    @TableField("kms_key_version")
    private Integer kmsKeyVersion;

    @TableField("kms_provider")
    private String kmsProvider;

    @TableField("root_key_version")
    private Long rootKeyVersion;

    @TableField("derivation_version")
    private String derivationVersion;

    @TableField("algorithm")
    private String algorithm;

    @TableField("key_spec")
    private String keySpec;

    @TableField("key_state")
    private String keyState;

    @TableField("valid_from")
    private LocalDateTime validFrom;

    @TableField("valid_to")
    private LocalDateTime validTo;

    @TableField("decrypt_until")
    private LocalDateTime decryptUntil;

    @TableField("wrap_mode")
    private String wrapMode;

    @TableField("last_recipient_cert_sn")
    private String lastRecipientCertSn;

    @TableField("request_id")
    private String requestId;

    @TableField("operation_id")
    private String operationId;

    @TableField("superseded_by_id")
    private Long supersededById;

    @TableField("logical_identity_digest")
    private byte[] logicalIdentityDigest;

    @TableField("recovery_count")
    private int recoveryCount;

    @TableField("last_recovery_request_id")
    private String lastRecoveryRequestId;

    @TableField("request_digest")
    private String requestDigest;

    @TableField("policy_version")
    private String policyVersion;

    @TableField("fail_reason")
    private String failReason;

    @TableField("last_attempt_time")
    private LocalDateTime lastAttemptTime;
}
