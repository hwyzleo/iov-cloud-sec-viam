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
 * 准入裁决审计表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-005）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_admission_audit")
public class DecisionAuditPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("admission_decision_id")
    private String admissionDecisionId;

    @TableField("decision")
    private String decision;

    @TableField("reason")
    private String reason;

    @TableField("uid_digest")
    private String uidDigest;

    @TableField("cert_serial_digest")
    private String certSerialDigest;

    @TableField("source_ip_digest")
    private String sourceIpDigest;

    @TableField("vin")
    private String vin;

    @TableField("bind_status")
    private String bindStatus;

    @TableField("cert_status")
    private String certStatus;

    @TableField("device_status")
    private String deviceStatus;

    @TableField("bind_version")
    private Long bindVersion;

    @TableField("snapshot_digest")
    private String snapshotDigest;

    @TableField("snapshot_expires_at")
    private LocalDateTime snapshotExpiresAt;

    @TableField("caller")
    private String caller;

    @TableField("dependency_outcome")
    private String dependencyOutcome;

    @TableField("pki_latency_ms")
    private Long pkiLatencyMs;

    @TableField("response_time_ms")
    private Long responseTimeMs;

    @TableField("decision_at")
    private LocalDateTime decisionAt;
}
