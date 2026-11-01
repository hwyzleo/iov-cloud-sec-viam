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

import java.time.Instant;
import java.time.LocalDateTime;

/**
 * 设备安全主体表 PO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_security_principal")
public class SecurityPrincipalPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("principal_id")
    private String principalId;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("source_system")
    private String sourceSystem;

    @TableField("source_ref_id")
    private String sourceRefId;

    @TableField("status")
    private String status;

    @TableField("block_reason")
    private String blockReason;

    @TableField("block_effective_at")
    private LocalDateTime blockEffectiveAt;

    @TableField("created_at")
    private LocalDateTime createdAt;
}
