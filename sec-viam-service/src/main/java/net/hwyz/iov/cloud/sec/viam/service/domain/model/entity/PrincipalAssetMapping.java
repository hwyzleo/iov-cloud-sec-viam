package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 安全主体资产映射实体（SEC-VIAM-DSN-CR-001 / D-VIAM-003 / FR-VIAM-001）
 * <p>
 * VMD 保留资产与绑定权威；VIAM 的身份关联由受信入站登记、VMD 事实和迁入凭据记录建立。
 * 本映射为 VIAM 侧只读投影与主体关联，不反向修改 VMD 绑定。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PrincipalAssetMapping {

    /** 安全主体ID */
    private String principalId;

    /** 车辆VIN（资产映射） */
    private String vin;

    /** 设备物理实例序列号 */
    private String deviceSn;

    /** 创建时 active vehicle_part.id（VMD 事实） */
    private Long bindingId;

    /** 设备物理实例，关联 part_info.id */
    private Long partId;

    /** 绑定版本（VMD 事实） */
    private Long bindingVersion;

    /** 绑定最近更新时间（VMD 事实） */
    private Instant bindingUpdatedAt;

    /** 设备类别 */
    private String deviceCategory;

    /** 映射状态：ACTIVE/SUPERSEDED/UNBOUND */
    private MappingState state;

    /** 映射状态 */
    public enum MappingState {
        ACTIVE, SUPERSEDED, UNBOUND
    }

    /**
     * 以 VMD 新事实更新绑定版本（只读投影同步，不修改 VMD）。
     */
    public void syncBindingFact(Long newBindingVersion, Instant updatedAt) {
        this.bindingVersion = newBindingVersion;
        this.bindingUpdatedAt = updatedAt;
        this.state = MappingState.ACTIVE;
    }

    /**
     * 解绑：映射转 UNBOUND（保留历史，不删除）。
     */
    public void unbind() {
        this.state = MappingState.UNBOUND;
    }
}
