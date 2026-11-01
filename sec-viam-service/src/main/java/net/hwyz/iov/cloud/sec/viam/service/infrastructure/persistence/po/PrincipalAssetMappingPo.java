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
 * 安全主体资产映射表 PO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_principal_asset_mapping")
public class PrincipalAssetMappingPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("principal_id")
    private String principalId;

    @TableField("vin")
    private String vin;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("binding_id")
    private Long bindingId;

    @TableField("part_id")
    private Long partId;

    @TableField("binding_version")
    private Long bindingVersion;

    @TableField("binding_updated_at")
    private LocalDateTime bindingUpdatedAt;

    @TableField("device_category")
    private String deviceCategory;

    @TableField("status")
    private String status;
}
