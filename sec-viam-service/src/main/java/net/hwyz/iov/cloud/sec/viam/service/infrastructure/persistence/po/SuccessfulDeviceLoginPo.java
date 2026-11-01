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
 * 设备成功接入记录表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-005）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_successful_login")
public class SuccessfulDeviceLoginPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("login_id")
    private String loginId;

    @TableField("principal_id")
    private String principalId;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("vin")
    private String vin;

    @TableField("admission_decision_id")
    private String admissionDecisionId;

    @TableField("session_id")
    private String sessionId;

    @TableField("connection_generation")
    private long connectionGeneration;

    @TableField("cert_serial")
    private String certSerial;

    @TableField("occurred_at")
    private LocalDateTime occurredAt;

    @TableField("time_source")
    private String timeSource;

    @TableField("event_source")
    private String eventSource;
}
