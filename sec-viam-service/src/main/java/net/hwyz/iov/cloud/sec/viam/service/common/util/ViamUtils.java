package net.hwyz.iov.cloud.sec.viam.service.common.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;

/**
 * VIAM 通用工具（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
public final class ViamUtils {

    private ViamUtils() {
    }

    /**
     * 归一化 HSM UID（trim + 大写）。
     */
    public static String normalizeUid(String uid) {
        if (uid == null) {
            return null;
        }
        String normalized = uid.trim().toUpperCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }

    /**
     * SHA-256 hex 摘要（用于审计摘要/事件幂等，禁止用于密钥材料）。
     */
    public static String sha256Hex(String input) {
        if (input == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * SHA-256 hex 摘要（bytes 重载，用于 canonical payload 摘要）。
     */
    public static String sha256Hex(byte[] input) {
        if (input == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * 生成准入裁决ID（幂等键）。
     */
    public static String newAdmissionDecisionId() {
        return "ADM-" + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 生成主体ID（稳定，非 hsmUid）。
     */
    public static String newPrincipalId(String hsmUid) {
        return "PR-" + sha256Hex(normalizeUid(hsmUid)).substring(0, 24);
    }

    /**
     * 生成登录记录ID（事件幂等键）。
     */
    public static String newLoginId(String hsmUid, long generation) {
        return "LG-" + sha256Hex(normalizeUid(hsmUid) + "|" + generation).substring(0, 32);
    }

    /**
     * 规范化证书序列号（小写 hex，去冒号）。
     */
    public static String canonicalCertSn(String certSn) {
        if (certSn == null) {
            return null;
        }
        return certSn.replace(":", "").toLowerCase(Locale.ROOT);
    }
}
