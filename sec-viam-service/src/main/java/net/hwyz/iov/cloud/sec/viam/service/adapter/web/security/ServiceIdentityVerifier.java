package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.security.ViamServiceAuthHeaders;
import net.hwyz.iov.cloud.sec.viam.api.security.ViamServiceSignature;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * 服务身份验签器（G-4）。
 * <p>
 * 校验签名头完整性、audience、时间戳窗口、nonce 重放、Secret 解析与 HMAC-SHA256 签名。
 * 任何环节不确定一律 fail-closed（403）。验签通过后返回 {@link WorkloadContext}，
 * 身份映射字段（clientId）仅来自验签后的签名头，禁止从请求体自报。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ServiceIdentityVerifier {

    private final ServiceIdentityProperties properties;
    private final ServiceIdentitySecrets secrets;
    private final NonceReplayGuard nonceReplayGuard;

    public ServiceIdentityVerifier(ServiceIdentityProperties properties,
                                   ServiceIdentitySecrets secrets,
                                   NonceReplayGuard nonceReplayGuard) {
        this.properties = properties;
        this.secrets = secrets;
        this.nonceReplayGuard = nonceReplayGuard;
    }

    /**
     * 验签并建立 workload 上下文。
     *
     * @param request 原始请求（含签名头）
     * @param body    原始 body bytes（用于摘要校验）
     * @return 认证后的调用方身份
     */
    public WorkloadContext verify(HttpServletRequest request, byte[] body) {
        String clientId = header(request, ViamServiceAuthHeaders.CLIENT_ID);
        String keyId = header(request, ViamServiceAuthHeaders.KEY_ID);
        String audience = header(request, ViamServiceAuthHeaders.AUDIENCE);
        String method = header(request, ViamServiceAuthHeaders.METHOD);
        String path = header(request, ViamServiceAuthHeaders.PATH);
        String bodyDigest = header(request, ViamServiceAuthHeaders.BODY_DIGEST);
        String timestamp = header(request, ViamServiceAuthHeaders.TIMESTAMP);
        String nonce = header(request, ViamServiceAuthHeaders.NONCE);
        String signature = header(request, ViamServiceAuthHeaders.SIGNATURE);
        String algorithm = header(request, ViamServiceAuthHeaders.ALGORITHM);

        // 1. 头完整性
        if (clientId == null || keyId == null || audience == null || method == null
                || path == null || bodyDigest == null || timestamp == null || nonce == null
                || signature == null) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_MISSING);
        }
        // 2. audience 固定
        if (!ViamServiceSignature.constantTimeEquals(properties.getAudience(), audience)) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_AUDIENCE_MISMATCH);
        }
        // 3. 算法版本
        if (!ViamServiceSignature.ALGORITHM_V1.equals(algorithm)) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN,
                    "不支持的签名算法: " + algorithm);
        }
        // 4. body 摘要与实际 body 一致（防签名与载荷分离）
        if (body == null || !ViamServiceSignature.constantTimeEquals(bodyDigest, sha256Hex(body))) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN,
                    "body摘要与签名头不一致");
        }
        // 5. 时间戳窗口
        long ts;
        try {
            ts = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_EXPIRED, "时间戳非法");
        }
        long now = System.currentTimeMillis();
        long window = properties.getTimestampWindowSeconds() * 1000L;
        if (Math.abs(now - ts) > window) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_EXPIRED);
        }
        // 6. nonce 重放
        if (!nonceReplayGuard.tryClaim(clientId, nonce, properties.getTimestampWindowSeconds())) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_REPLAYED);
        }
        // 7. Secret 解析 + 签名校验（常量时间比较）
        byte[] secret = secrets.secretBytes(clientId, keyId);
        String canonical = ViamServiceSignature.canonicalString(
                clientId, keyId, audience, method, path, bodyDigest, timestamp, nonce);
        String expected = ViamServiceSignature.sign(secret, canonical);
        if (!ViamServiceSignature.constantTimeEquals(expected, signature)) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN,
                    "签名校验失败");
        }
        return new WorkloadContext(clientId, keyId, audience);
    }

    private static String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? null : value.trim();
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(digest.digest(bytes));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /** body 摘要便捷方法（供测试/调用方复用） */
    public static String bodyDigest(byte[] body) {
        return sha256Hex(body == null ? new byte[0] : body);
    }
}
