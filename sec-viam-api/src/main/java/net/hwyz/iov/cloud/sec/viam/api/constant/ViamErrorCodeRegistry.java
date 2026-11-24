package net.hwyz.iov.cloud.sec.viam.api.constant;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * VIAM 错误码注册表（SEC-VIAM-DSN-CR-005 / 错误码治理）。
 * <p>
 * 对齐平台错误码治理范式：错误码必须可登记、可校验、可查询。类初始化时 fail-fast 校验：
 * </p>
 * <ul>
 *   <li>{@link ViamErrorCode} 全部匹配 {@code ^702\d{3}$} 且不重复；</li>
 *   <li>{@link ViamLegacyCodeMapping} 的旧码格式合法（806xxx / 401xxx），目标新码必须在注册表内；</li>
 *   <li>旧码与新码不得互相污染（旧码退役不复用）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
public final class ViamErrorCodeRegistry {

    /**
     * VIAM 新错误码格式：702 + 3 位序号。
     */
    private static final Pattern CODE_PATTERN = Pattern.compile("^702\\d{3}$");

    /**
     * 旧错误码格式：VMD 806xxx / TSP 401xxx。
     */
    private static final Pattern LEGACY_CODE_PATTERN = Pattern.compile("^(806|401)\\d{3}$");

    private static final Map<String, ViamErrorCode> CODE_MAP;

    static {
        Map<String, ViamErrorCode> codes = new LinkedHashMap<>();
        for (ViamErrorCode errorCode : ViamErrorCode.values()) {
            if (!CODE_PATTERN.matcher(errorCode.getCode()).matches()) {
                throw new IllegalStateException(String.format(
                        "VIAM错误码格式非法: %s=%s，必须匹配 %s",
                        errorCode.name(), errorCode.getCode(), CODE_PATTERN.pattern()));
            }
            ViamErrorCode existing = codes.put(errorCode.getCode(), errorCode);
            if (existing != null) {
                throw new IllegalStateException(String.format(
                        "VIAM错误码重复: %s 同时登记于 %s 与 %s",
                        errorCode.getCode(), existing.name(), errorCode.name()));
            }
        }
        ViamLegacyCodeMapping.entries().forEach((legacyCode, newCode) -> {
            if (!LEGACY_CODE_PATTERN.matcher(legacyCode).matches()) {
                throw new IllegalStateException(String.format(
                        "VIAM旧错误码格式非法: %s，必须匹配 %s", legacyCode, LEGACY_CODE_PATTERN.pattern()));
            }
            if (!codes.containsKey(newCode)) {
                throw new IllegalStateException(String.format(
                        "VIAM旧错误码映射目标未登记: %s -> %s", legacyCode, newCode));
            }
        });
        CODE_MAP = Collections.unmodifiableMap(codes);
    }

    private ViamErrorCodeRegistry() {
    }

    /**
     * 按错误码查询（702xxx）。
     *
     * @param code 错误码
     * @return 命中的错误码枚举，未登记返回 empty
     */
    public static Optional<ViamErrorCode> find(String code) {
        return code == null ? Optional.empty() : Optional.ofNullable(CODE_MAP.get(code));
    }

    /**
     * 按错误码查询（702xxx），未登记即抛错。
     *
     * @param code 错误码
     * @return 命中的错误码枚举
     */
    public static ViamErrorCode of(String code) {
        return find(code).orElseThrow(() ->
                new IllegalArgumentException("未登记的VIAM错误码: " + code));
    }

    /**
     * 已登记错误码快照（按枚举声明顺序）。
     *
     * @return 只读映射
     */
    public static Map<String, ViamErrorCode> codes() {
        return CODE_MAP;
    }
}
