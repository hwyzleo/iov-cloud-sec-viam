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
 * 业务密钥开通批次表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_business_key_provisioning")
public class ProvisioningBatchPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("request_id")
    private String requestId;

    @TableField("request_digest")
    private String requestDigest;

    @TableField("ack_digest")
    private String ackDigest;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("binding_id")
    private Long bindingId;

    @TableField("part_id")
    private Long partId;

    @TableField("hsm_uid_digest")
    private String hsmUidDigest;

    @TableField("certificate_sn_digest")
    private String certificateSnDigest;

    @TableField("business_domain")
    private String businessDomain;

    @TableField("status")
    private String status;

    @TableField("fail_reason")
    private String failReason;

    @TableField("response_payload")
    private byte[] responsePayload;

    @TableField("response_ref")
    private String responseRef;

    @TableField("response_digest")
    private String responseDigest;

    @TableField("response_codec_version")
    private String responseCodecVersion;

    @TableField("response_persisted_at")
    private LocalDateTime responsePersistedAt;

    @TableField("lifecycle_profile")
    private String lifecycleProfile;

    @TableField("first_issued_at")
    private LocalDateTime firstIssuedAt;

    @TableField("ack_deadline_at")
    private LocalDateTime ackDeadlineAt;

    @TableField("immutable_content_digest")
    private String immutableContentDigest;

    @TableField("lease_seq")
    private Integer leaseSeq;

    @TableField("terminal_reason")
    private String terminalReason;

    @TableField("terminal_at")
    private LocalDateTime terminalAt;

    @TableField("started_at")
    private LocalDateTime startedAt;

    @TableField("acknowledged_at")
    private LocalDateTime acknowledgedAt;

    @TableField("completed_at")
    private LocalDateTime completedAt;
}
