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

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_security_operation_audit")
public class SecurityOperationAuditPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

        @TableField("operation_id")
    private String operationId;

    @TableField("principal_id")
    private String principalId;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("vin")
    private String vin;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("operation")
    private String operation;

    @TableField("security_version")
    private Long securityVersion;

    @TableField("reason")
    private String reason;

    @TableField("detail")
    private String detail;

    @TableField("operator_id")
    private String operatorId;

    @TableField("operator_name")
    private String operatorName;

    @TableField("caller_type")
    private String callerType;

    @TableField("occurred_at")
    private LocalDateTime occurredAt;

}
