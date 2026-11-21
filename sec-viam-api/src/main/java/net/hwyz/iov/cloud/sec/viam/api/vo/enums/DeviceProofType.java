package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 设备证明类型（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-1）
 * <ul>
 *   <li>{@link #MTLS_CERT}：证明体为本次连接实际叶子证书（Base64 DER 或 PEM）；
 *       设备身份取证书 Subject CN（= HSM UID），{@code deviceId} 仅作一致性交叉校验。</li>
 *   <li>{@link #KEY_SIGNATURE}：证明体为对 nonce 原文（UTF-8 字节）的签名（Base64）；
 *       设备定位依赖 {@code deviceId}（通常为 deviceSn），公钥取自 VIAM 已登记证书
 *       （经 PKI 按证书序列号重取，不落库）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
public enum DeviceProofType {

    /** mTLS 证书链证明 */
    MTLS_CERT,
    /** 私钥签名（nonce 绑定）证明 */
    KEY_SIGNATURE;

    public static DeviceProofType valOf(String val) {
        if (val == null) {
            return null;
        }
        return Arrays.stream(values())
                .filter(type -> type.name().equals(val.trim().toUpperCase(java.util.Locale.ROOT)))
                .findFirst()
                .orElse(null);
    }
}
