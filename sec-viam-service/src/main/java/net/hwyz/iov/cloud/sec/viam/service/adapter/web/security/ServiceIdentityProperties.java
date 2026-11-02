package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 服务身份映射与授权配置（SEC-VIAM-DSN-CR-001 / R1，G-4 平台内网信任链）。
 * <p>
 * 平台内网信任链：{@code X-Client-Id} 身份映射 + 受限网络可达性 + 外部网关边界 +
 * 接口授权矩阵 + fail-closed。无 HMAC Secret / keyId / 时间戳窗口 / nonce。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Component
@ConfigurationProperties(prefix = "viam.security.service-identity")
public class ServiceIdentityProperties {

    /** 是否启用服务身份映射与授权（真实入口默认 true；仅隔离测试环境可关闭，关闭时不得开放真实安全写入） */
    private boolean enabled = true;

    /** 每调用方允许的路径前缀（clientId → 前缀列表）；键集合即已登记调用方，缺失/空表示无任何服务接口权限 */
    private Map<String, List<String>> access = new HashMap<>();

    /** 跳过身份映射的健康/只读端点前缀（默认空；不得包含 /api/service/** 安全写入） */
    private List<String> unauthenticatedPrefixes = List.of();
}
