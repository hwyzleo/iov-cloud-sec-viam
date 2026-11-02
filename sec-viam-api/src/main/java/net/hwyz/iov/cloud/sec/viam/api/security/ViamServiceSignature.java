package net.hwyz.iov.cloud.sec.viam.api.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * VIAM 官方服务间签名原语（SEC-VIAM-DSN-CR-001 / G-4，单点定义）。
 * <p>
 * 供调用方（VAGW/OAPI）与 VIAM 验签端共同引用，避免各服务重复实现一套签名协议。
 * 签名覆盖调用方 ID、keyId、audience、HTTP method、规范化 path/query、原始 body digest、
 * timestamp、nonce；使用每调用方独立 Secret（HMAC-SHA256），常量时间比较由调用方配合
 * {@link #constantTimeEquals} 完成。本类不接触 Secret 正文的存储/注入，Secret 由部署方
 * 经环境变量注入。
 * </p>
 *
 * @author hwyz_leo
 */
public final class ViamServiceSignature {

    /** 当前签名算法版本 */
    public static final String ALGORITHM_V1 = "v1";

    /** 签名规范串分隔符 */
    private static final char SEP = '\n';

    private ViamServiceSignature() {
    }

    /**
     * 构造签名规范串（HMAC 输入）。各字段顺序固定，缺字段以空串占位。
     */
    public static String canonicalString(String clientId, String keyId, String audience,
                                         String method, String path, String bodyDigest,
                                         String timestamp, String nonce) {
        return String.join(String.valueOf(SEP),
                nz(clientId), nz(keyId), nz(audience),
                nz(method).toLowerCase(), nz(path), nz(bodyDigest),
                nz(timestamp), nz(nonce));
    }

    /**
     * 计算 HMAC-SHA256 签名（hex）。
     *
     * @param secret 调用方独立 Secret（Base64 解码后的原始字节，由部署方注入）
     */
    public static String sign(byte[] secret, String canonicalString) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(canonicalString.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 不可用", e);
        }
    }

    /**
     * 常量时间比较（防时序侧信道）。
     */
    public static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null || expected.length() != actual.length()) {
            return false;
        }
        int result = 0;
        byte[] a = expected.getBytes(StandardCharsets.UTF_8);
        byte[] b = actual.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    private static String nz(String value) {
        return value == null ? "" : value;
    }
}
