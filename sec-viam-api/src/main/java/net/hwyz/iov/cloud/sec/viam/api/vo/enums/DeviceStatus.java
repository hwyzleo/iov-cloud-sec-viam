package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 设备安全开通准入态枚举（SEC-VIAM-DSN-CR-001 / FR-VIAM-006）
 * <p>
 * 口径沿用安全开通状态机：PRE_ACTIVE / ACTIVATING / ACTIVE 可继续准入判定，
 * BLOCKED / RETIRED 拒绝。同名状态与 TSP 运营状态、VMD 整车生命周期分离，
 * 不顺带迁移整车生命周期。
 * </p>
 *
 * @author hwyz_leo
 */
public enum DeviceStatus {

    /** 待激活（尚未可信成功接入） */
    PRE_ACTIVE,
    /** 已接入，正在完成 V2C 初始密钥开通 */
    ACTIVATING,
    /** 完整用途集密钥均已导入确认 */
    ACTIVE,
    /** 安全封禁 */
    BLOCKED,
    /** 退役 */
    RETIRED;

    public static DeviceStatus valOf(String val) {
        return Arrays.stream(values())
                .filter(status -> status.name().equals(val))
                .findFirst()
                .orElse(null);
    }
}
