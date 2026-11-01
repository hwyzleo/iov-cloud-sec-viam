package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 设备接入准入请求VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * uid、certSerial、certFingerprint、leafCertificateDer 对所有设备准入请求均必填；
 * leafCertificateDer 为本次 EMQX mTLS 实际叶子证书的标准 Base64 编码 DER，解码后最大 8 KiB，
 * 仅用于本次裁决，VIAM 不落库、不进入审计正文或普通日志。
 * </p>
 *
 * @author hwyz_leo
 */
public enum BindStatus {

    /** 存在唯一 ACTIVE 绑定 */
    BOUND,
    /** 无 ACTIVE 绑定 */
    UNBOUND,
    /** 存在多条 ACTIVE 绑定（冲突，fail-closed） */
    CONFLICT,
    /** 尚未判定或不可确定 */
    UNKNOWN;

    public static BindStatus valOf(String val) {
        return Arrays.stream(values())
                .filter(status -> status.name().equals(val))
                .findFirst()
                .orElse(null);
    }
}
