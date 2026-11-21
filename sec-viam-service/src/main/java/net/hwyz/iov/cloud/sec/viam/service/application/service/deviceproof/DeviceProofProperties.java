package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * 设备证明校验配置（SEC-VIAM-DSN-CR-003 §13.7）
 * <p>
 * 全部为逻辑开关与固定语义，不含密码学材料；未启用视为不可用（fail-closed）。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Component
@ConfigurationProperties(prefix = "viam.device-proof")
public class DeviceProofProperties {

    /** 设备证明校验能力开关；关闭时一律返回依赖不可用（fail-closed），不返回通过 */
    private boolean enabled = true;

    /** nonce 一次性键有效期（默认 2 分钟） */
    private Duration nonceTtl = Duration.ofMinutes(2);

    /** 限流（按调用方服务身份 + 设备维度） */
    private RateLimit rateLimit = new RateLimit();

    /** 证明校验参数 */
    private Verify verify = new Verify();

    @Data
    public static class RateLimit {

        /** 每调用方每分钟允许次数 */
        private int perCallerPerMinute = 60;

        /** 每设备每分钟允许次数 */
        private int perDevicePerMinute = 12;
    }

    @Data
    public static class Verify {

        /** 单次校验总预算（含 PKI/Redis）；超出即 fail-closed */
        private Duration totalBudget = Duration.ofSeconds(1);

        /**
         * 吊销查询 OCSP 优先（声明性策略：实际 OCSP/CRL 执行与超时由 framework-security
         * PKI 证书状态能力（crypto.pki.revocation.*）落地，VIAM 不自建第二套 OCSP/CRL 客户端）。
         */
        private boolean ocspFirst = true;

        /**
         * CRL 兜底（声明性策略，同上由 framework PKI 证书状态能力执行）。
         */
        private boolean crlFallback = true;
    }
}
