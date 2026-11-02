package net.hwyz.iov.cloud.sec.viam.api.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 服务间签名原语单元测试（SEC-VIAM-DSN-CR-001 / G-4）
 * <p>
 * 验证规范串稳定性、HMAC 签名一致性、字段缺失/篡改与常量时间比较。
 * </p>
 *
 * @author hwyz_leo
 */
class ViamServiceSignatureTest {

    private static final byte[] SECRET = "test-secret-32-bytes-0123456789abcd".getBytes(StandardCharsets.UTF_8);

    @Test
    void canonicalStringIsStableAndOrderFixed() {
        String a = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "abc123", "1700000000000", "nonce-1");
        String b = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "abc123", "1700000000000", "nonce-1");
        assertEquals(a, b);
        // 顺序固定：交换两个字段后规范串必须不同
        String swapped = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "abc123", "nonce-1", "1700000000000");
        assertNotEquals(a, swapped);
    }

    @Test
    void signVerifyRoundTrip() {
        String canonical = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "abc123", "1700000000000", "nonce-1");
        String sig = ViamServiceSignature.sign(SECRET, canonical);
        assertTrue(ViamServiceSignature.constantTimeEquals(sig, ViamServiceSignature.sign(SECRET, canonical)));
    }

    @Test
    void differentSecretOrPayloadFails() {
        String canonical = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "abc123", "1700000000000", "nonce-1");
        String sig = ViamServiceSignature.sign(SECRET, canonical);
        // 错误 Secret
        byte[] other = "another-secret-value-0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        assertFalse(ViamServiceSignature.constantTimeEquals(sig, ViamServiceSignature.sign(other, canonical)));
        // 篡改 body digest
        String tampered = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "xyz999", "1700000000000", "nonce-1");
        assertFalse(ViamServiceSignature.constantTimeEquals(sig, ViamServiceSignature.sign(SECRET, tampered)));
        // 篡改 clientId（冒充 VAGW 被拒绝）
        String spoofed = ViamServiceSignature.canonicalString(
                "ATTACKER", "k1", "sec-viam", "POST", "/api/service/deviceAdmission/v1/decide",
                "abc123", "1700000000000", "nonce-1");
        assertFalse(ViamServiceSignature.constantTimeEquals(sig, ViamServiceSignature.sign(SECRET, spoofed)));
    }

    @Test
    void missingFieldsFailClosed() {
        // 缺 nonce / timestamp 的规范串与完整串不同，无法复用签名
        String full = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/path", "d", "t", "n");
        String missing = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/path", "d", "t", "");
        assertNotEquals(full, missing);
    }
}
