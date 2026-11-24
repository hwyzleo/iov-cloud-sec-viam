package net.hwyz.iov.cloud.sec.viam.service.adapter.kafka;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 绑定事实自动登记配置（SEC-VIAM-DSN-CR-006 / D-VIAM-031）
 * <p>
 * 默认仅登记可签发类别（TBOX、IVI）；CCU/ADAS 等类别需在具备 Profile 与签发能力后另立 CR 放开。
 * </p>
 *
 * @author hwyz_leo
 * @since 2026-11-24
 */
@Data
@Component
@ConfigurationProperties(prefix = "viam.binding-enrollment")
public class BindingEnrollmentProperties {

    /** 是否启用自动登记（关闭后退化为仅落 Inbox 跳过） */
    private boolean enabled = true;

    /** 允许登记的设备类别（规范化后比较，默认 TBOX/IVI） */
    private List<String> allowedCategories = List.of("TBOX", "IVI");

    /** 登记来源系统（受信来源，写入 tb_viam_security_principal.source_system） */
    private String enrollSourceSystem = "VMD_FACT";

    /** 单次快照收敛上限，超出即隔离告警 */
    private int maxSnapshotBindings = 32;
}
