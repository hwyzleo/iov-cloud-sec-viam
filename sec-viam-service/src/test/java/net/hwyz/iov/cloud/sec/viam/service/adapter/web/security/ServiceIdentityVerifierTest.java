package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.security.ViamServiceAuthHeaders;
import net.hwyz.iov.cloud.sec.viam.api.security.ViamServiceSignature;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * 服务身份验签单元测试（SEC-VIAM-DSN-CR-001 / G-4）
 * <p>
 * 覆盖缺头/audience/算法/body摘要/时间戳/nonce重放/签名失败 fail-closed 及成功路径。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class ServiceIdentityVerifierTest {

    private static final byte[] VAGW_SECRET = "vagw-secret-32-bytes-0123456789abcd".getBytes(StandardCharsets.UTF_8);
    private static final String VAGW_SECRET_B64 = Base64.getEncoder().encodeToString(VAGW_SECRET);

    @Mock
    private HttpServletRequest request;

    private final Map<String, String> headers = new HashMap<>();

    private ServiceIdentityProperties properties;
    private ServiceIdentitySecrets secrets;
    private NonceReplayGuard guard;
    private ServiceIdentityVerifier verifier;

    @BeforeEach
    void setUp() {
        properties = new ServiceIdentityProperties();
        properties.setAudience("sec-viam");
        properties.setTimestampWindowSeconds(300);
        properties.setCurrentKeyIds(Map.of("VAGW", "k1"));
        properties.setSecrets(Map.of("VAGW", Map.of("k1", VAGW_SECRET_B64)));
        properties.setAccess(Map.of("VAGW", List.of("/api/service/")));
        secrets = new ServiceIdentitySecrets(properties);
        guard = new InMemoryNonceReplayGuard();
        verifier = new ServiceIdentityVerifier(properties, secrets, guard);
        when(request.getHeader(anyString())).thenAnswer(inv -> headers.get(inv.getArgument(0)));
    }

    private void put(String name, String value) {
        headers.put(name, value);
    }

    private void signHeaders(String clientId, String keyId, String method, String path, byte[] body,
                             String timestamp, String nonce) {
        String digest = ServiceIdentityVerifier.bodyDigest(body);
        put(ViamServiceAuthHeaders.CLIENT_ID, clientId);
        put(ViamServiceAuthHeaders.KEY_ID, keyId);
        put(ViamServiceAuthHeaders.AUDIENCE, "sec-viam");
        put(ViamServiceAuthHeaders.METHOD, method);
        put(ViamServiceAuthHeaders.PATH, path);
        put(ViamServiceAuthHeaders.BODY_DIGEST, digest);
        put(ViamServiceAuthHeaders.TIMESTAMP, timestamp);
        put(ViamServiceAuthHeaders.NONCE, nonce);
        put(ViamServiceAuthHeaders.ALGORITHM, ViamServiceSignature.ALGORITHM_V1);
        String canonical = ViamServiceSignature.canonicalString(
                clientId, keyId, "sec-viam", method, path, digest, timestamp, nonce);
        put(ViamServiceAuthHeaders.SIGNATURE, ViamServiceSignature.sign(VAGW_SECRET, canonical));
    }

    @Test
    void validSignatureBuildsContext() {
        signHeaders("VAGW", "k1", "POST", "/api/service/deviceAdmission/v1/decide",
                "{\"uid\":\"HSM-1\"}".getBytes(StandardCharsets.UTF_8),
                String.valueOf(System.currentTimeMillis()), "nonce-1");
        WorkloadContext ctx = verifier.verify(request, "{\"uid\":\"HSM-1\"}".getBytes(StandardCharsets.UTF_8));
        assertEquals("VAGW", ctx.clientId());
    }

    @Test
    void missingHeadersFailClosed() {
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, new byte[0]));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_MISSING.getCode(), e.getCode());
    }

    @Test
    void wrongAudienceFails() {
        signHeaders("VAGW", "k1", "POST", "/path", new byte[0],
                String.valueOf(System.currentTimeMillis()), "nonce-2");
        put(ViamServiceAuthHeaders.AUDIENCE, "other-service");
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, new byte[0]));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_AUDIENCE_MISMATCH.getCode(), e.getCode());
    }

    @Test
    void bodyDigestMismatchFails() {
        signHeaders("VAGW", "k1", "POST", "/path", "expected-body".getBytes(StandardCharsets.UTF_8),
                String.valueOf(System.currentTimeMillis()), "nonce-3");
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, "tampered-body".getBytes(StandardCharsets.UTF_8)));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN.getCode(), e.getCode());
    }

    @Test
    void expiredTimestampFails() {
        signHeaders("VAGW", "k1", "POST", "/path", new byte[0],
                String.valueOf(System.currentTimeMillis() - 3600_000L), "nonce-4");
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, new byte[0]));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_EXPIRED.getCode(), e.getCode());
    }

    @Test
    void nonceReplayFails() {
        String ts = String.valueOf(System.currentTimeMillis());
        signHeaders("VAGW", "k1", "POST", "/path", new byte[0], ts, "nonce-replay");
        assertTrue(verifier.verify(request, new byte[0]).clientId().equals("VAGW"));
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, new byte[0]));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_REPLAYED.getCode(), e.getCode());
    }

    @Test
    void spoofedClientIdFails() {
        // 攻击者伪造 clientId=VAGW，但用自己 Secret 签名（与 VAGW 注册 Secret 不同）
        byte[] attackerSecret = "attacker-secret-32-bytes-9876543210abcd".getBytes(StandardCharsets.UTF_8);
        String ts = String.valueOf(System.currentTimeMillis());
        String digest = ServiceIdentityVerifier.bodyDigest(new byte[0]);
        put(ViamServiceAuthHeaders.CLIENT_ID, "VAGW");
        put(ViamServiceAuthHeaders.KEY_ID, "k1");
        put(ViamServiceAuthHeaders.AUDIENCE, "sec-viam");
        put(ViamServiceAuthHeaders.METHOD, "POST");
        put(ViamServiceAuthHeaders.PATH, "/path");
        put(ViamServiceAuthHeaders.BODY_DIGEST, digest);
        put(ViamServiceAuthHeaders.TIMESTAMP, ts);
        put(ViamServiceAuthHeaders.NONCE, "nonce-spoof");
        put(ViamServiceAuthHeaders.ALGORITHM, ViamServiceSignature.ALGORITHM_V1);
        String canonical = ViamServiceSignature.canonicalString(
                "VAGW", "k1", "sec-viam", "POST", "/path", digest, ts, "nonce-spoof");
        put(ViamServiceAuthHeaders.SIGNATURE, ViamServiceSignature.sign(attackerSecret, canonical));
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, new byte[0]));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN.getCode(), e.getCode());
    }

    @Test
    void unknownClientSecretFails() {
        signHeaders("UNKNOWN_CLIENT", "k1", "POST", "/path", new byte[0],
                String.valueOf(System.currentTimeMillis()), "nonce-5");
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> verifier.verify(request, new byte[0]));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN.getCode(), e.getCode());
    }

    @Test
    void accessPolicyDeniesUnauthorizedPath() {
        signHeaders("VAGW", "k1", "POST", "/api/service/deviceAdmission/v1/decide",
                "{\"uid\":\"HSM-1\"}".getBytes(StandardCharsets.UTF_8),
                String.valueOf(System.currentTimeMillis()), "nonce-6");
        WorkloadContext ctx = verifier.verify(request, "{\"uid\":\"HSM-1\"}".getBytes(StandardCharsets.UTF_8));
        ServiceAccessPolicy policy = new ServiceAccessPolicy(properties);
        policy.requireAccess(ctx.clientId(), "/api/service/deviceAdmission/v1/decide");
        // 未登记权限的调用方被拒绝
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> policy.requireAccess("OAPI_UNREGISTERED", "/api/service/deviceAdmission/v1/decide"));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED.getCode(), e.getCode());
    }
}
