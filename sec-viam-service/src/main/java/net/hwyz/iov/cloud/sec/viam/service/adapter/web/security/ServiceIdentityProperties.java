package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 服务身份认证配置（G-4）。
 * <p>
 * 每调用方独立 Secret（Base64，经环境变量注入，禁止 Nacos/日志）；
 * keyId 支持轮换：{@code secrets.<clientId>.<keyId>} 多版本共存，新签名用 currentKeyId。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Component
@ConfigurationProperties(prefix = "viam.security.service-identity")
public class ServiceIdentityProperties {

    /** 是否启用服务身份认证（生产必须 true；仅隔离测试环境可关闭，但关闭时不得开放真实安全写入） */
    private boolean enabled = true;

    /** 固定 audience（目标服务） */
    private String audience = "sec-viam";

    /** 时间戳有效窗口（秒） */
    private long timestampWindowSeconds = 300;

    /** 每调用方当前 keyId（clientId → keyId） */
    private Map<String, String> currentKeyIds = new HashMap<>();

    /** 每调用方多版本 Secret（clientId → keyId → Base64 Secret） */
    private Map<String, Map<String, String>> secrets = new HashMap<>();

    /** 每调用方允许的路径前缀（clientId → 前缀列表），空/缺失表示该调用方无任何服务接口权限 */
    private Map<String, java.util.List<String>> access = new HashMap<>();

    /** 跳过认证的健康/只读端点前缀（默认空；不得包含 /api/service/** 安全写入） */
    private java.util.List<String> unauthenticatedPrefixes = java.util.List.of();
}
