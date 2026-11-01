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
 * 业务密钥开通批次明细表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_business_key_provisioning_item")
public class ProvisioningItemPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("provisioning_id")
    private Long provisioningId;

    @TableField("purpose")
    private String purpose;

    @TableField("key_id")
    private String keyId;

    @TableField("business_key_version")
    private Long businessKeyVersion;

    @TableField("directory_key_id")
    private Long directoryKeyId;

    @TableField("operation_id")
    private String operationId;

    @TableField("root_key_version")
    private Long rootKeyVersion;

    @TableField("derivation_version")
    private String derivationVersion;

    @TableField("recipient_cert_fingerprint_digest")
    private String recipientCertFingerprintDigest;

    @TableField("envelope_format")
    private String envelopeFormat;

    @TableField("wrapping_suite")
    private String wrappingSuite;

    @TableField("core_envelope_digest")
    private byte[] coreEnvelopeDigest;

    @TableField("wire_envelope_digest")
    private byte[] wireEnvelopeDigest;

    @TableField("aad_profile_id")
    private String aadProfileId;

    @TableField("parameters_digest")
    private byte[] parametersDigest;

    @TableField("wrapped_key_digest")
    private byte[] wrappedKeyDigest;

    @TableField("recipient_cert_digest")
    private byte[] recipientCertDigest;

    @TableField("item_wire_offset")
    private Integer itemWireOffset;

    @TableField("item_wire_length")
    private Integer itemWireLength;

    @TableField("device_result")
    private String deviceResult;

    @TableField("import_proof_digest")
    private String importProofDigest;

    @TableField("confirmed_at")
    private LocalDateTime confirmedAt;
}
