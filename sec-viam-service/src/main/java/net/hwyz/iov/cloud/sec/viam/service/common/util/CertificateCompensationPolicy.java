package net.hwyz.iov.cloud.sec.viam.service.common.util;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 人工补申请类别—Profile 治理策略（SEC-VIAM-DSN-CR-004 / D-VIAM-023）
 * <p>
 * 服务端固定允许组合（规范化后精确匹配），前端联动只用于减少误操作，不能替代本门禁：
 * <ul>
 *   <li>{@code TBOX → TBOX_TSP_CLIENT}</li>
 *   <li>{@code IVI → IVI_DEVICE_IDENTITY}</li>
 * </ul>
 * 其他或交叉组合一律拒绝（702207），不得放行任意 Profile 字符串进入 PKI。
 * </p>
 *
 * @author hwyz_leo
 */
public final class CertificateCompensationPolicy {

    /** TBOX 设备类别 */
    public static final String CATEGORY_TBOX = "TBOX";

    /** IVI 设备类别 */
    public static final String CATEGORY_IVI = "IVI";

    /** TBOX 设备身份证书 Profile（沿用既有已登记 Profile） */
    public static final String PROFILE_TBOX = "TBOX_TSP_CLIENT";

    /** IVI 设备身份证书 Profile（FW-SEC-DSN-CR-022 登记） */
    public static final String PROFILE_IVI = "IVI_DEVICE_IDENTITY";

    private static final Map<String, String> ALLOWED = Map.of(
            CATEGORY_TBOX, PROFILE_TBOX,
            CATEGORY_IVI, PROFILE_IVI);

    private CertificateCompensationPolicy() {
    }

    /**
     * 规范化类别/Profile 取值（trim + 大写，空值返回 null）。
     */
    public static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }

    /**
     * 类别对应的唯一允许 Profile；类别未知返回 null。
     */
    public static String profileForCategory(String deviceCategory) {
        String category = normalize(deviceCategory);
        return category == null ? null : ALLOWED.get(category);
    }

    /**
     * 类别—Profile 组合是否被允许（两端均规范化后精确匹配）。
     */
    public static boolean isAllowed(String deviceCategory, String certificateProfile) {
        String expected = profileForCategory(deviceCategory);
        String profile = normalize(certificateProfile);
        return expected != null && expected.equals(profile);
    }

    /**
     * 允许的 Profile 集合（只读，供诊断/测试断言）。
     */
    public static Set<String> allowedProfiles() {
        return Set.copyOf(ALLOWED.values());
    }
}
