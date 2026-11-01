package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 证书状态枚举（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * {@link #VALID} 表示吊销查询得到确定有效且未过期；不确定一律不得伪造为 VALID。
 * </p>
 *
 * @author hwyz_leo
 */
public enum CertificateStatus {

    /** 确定有效（吊销查询 GOOD 且未过期） */
    VALID,
    /** 已被吊销 */
    REVOKED,
    /** 已过期 */
    EXPIRED,
    /** 未知/依赖不可用，fail-closed */
    UNKNOWN;

    public static CertificateStatus valOf(String val) {
        return Arrays.stream(values())
                .filter(status -> status.name().equals(val))
                .findFirst()
                .orElse(null);
    }
}
