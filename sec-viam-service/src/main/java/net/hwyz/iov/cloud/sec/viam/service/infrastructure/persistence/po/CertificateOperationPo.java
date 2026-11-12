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
 * 证书人工操作审计表 PO（SEC-VIAM-DSN-CR-002 / D-VIAM-013）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_certificate_operation")
public class CertificateOperationPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("operation_id")
    private String operationId;

    @TableField("request_id")
    private String requestId;

    @TableField("action")
    private String action;

    @TableField("operator_id")
    private String operatorId;

    @TableField("operator_name")
    private String operatorName;

    @TableField("reason")
    private String reason;

    @TableField("ticket_no")
    private String ticketNo;

    @TableField("original_request_id")
    private String originalRequestId;

    @TableField("before_status")
    private String beforeStatus;

    @TableField("after_status")
    private String afterStatus;

    @TableField("request_digest")
    private String requestDigest;

    @TableField("result")
    private String result;

    @TableField("error_code")
    private String errorCode;

    @TableField("source_ip")
    private String sourceIp;

    @TableField("user_agent")
    private String userAgent;

    @TableField("occurred_at")
    private LocalDateTime occurredAt;
}
