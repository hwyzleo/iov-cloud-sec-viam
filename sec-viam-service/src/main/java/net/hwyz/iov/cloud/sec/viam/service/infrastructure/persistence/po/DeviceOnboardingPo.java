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
 * 设备安全开通状态表 PO（SEC-VIAM-DSN-CR-001 / FR-VIAM-006）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_onboarding")
public class DeviceOnboardingPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("principal_id")
    private String principalId;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("vin")
    private String vin;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("state")
    private String state;

    @TableField("first_login_time")
    private LocalDateTime firstLoginTime;

    @TableField("last_login_time")
    private LocalDateTime lastLoginTime;

    @TableField("legacy_active_time")
    private LocalDateTime legacyActiveTime;

    @TableField("block_reason")
    private String blockReason;

    @TableField("block_effective_at")
    private LocalDateTime blockEffectiveAt;

    @TableField("activate_version")
    private long activateVersion;
}
