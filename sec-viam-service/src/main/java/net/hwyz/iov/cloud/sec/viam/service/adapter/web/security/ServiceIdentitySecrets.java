package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

/**
 * 调用方 Secret 注册表（G-4）。
 * <p>
 * 按 {@code clientId + keyId} 解析注入的 Base64 Secret；支持轮换（多 keyId 共存）。
 * 解析失败/未配置一律 fail-closed。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
public class ServiceIdentitySecrets {

    private final ServiceIdentityProperties properties;

    public ServiceIdentitySecrets(ServiceIdentityProperties properties) {
        this.properties = properties;
    }

    /**
     * 解析调用方当前 keyId。
     */
    public String currentKeyId(String clientId) {
        Map<String, String> current = properties.getCurrentKeyIds();
        return current == null ? null : current.get(clientId);
    }

    /**
     * 按 keyId 解析 Secret 原始字节；未配置/非法 fail-closed。
     */
    public byte[] secretBytes(String clientId, String keyId) {
        Map<String, Map<String, String>> secrets = properties.getSecrets();
        if (secrets == null || clientId == null || keyId == null) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN,
                    "调用方Secret未配置: clientId=" + clientId);
        }
        Map<String, String> versions = secrets.get(clientId);
        String base64 = versions == null ? null : versions.get(keyId);
        if (base64 == null || base64.isBlank()) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN,
                    "调用方Secret未配置: clientId=" + clientId + ", keyId=" + keyId);
        }
        try {
            byte[] raw = Base64.getDecoder().decode(base64.trim());
            if (raw.length < 16) {
                throw new ViamServiceException(ViamErrorCode.CONFIGURATION_INVALID,
                        "调用方Secret长度非法（需≥16字节）: clientId=" + clientId);
            }
            return raw;
        } catch (IllegalArgumentException e) {
            throw new ViamServiceException(ViamErrorCode.CONFIGURATION_INVALID,
                    "调用方Secret非Base64: clientId=" + clientId);
        }
    }
}
