package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * nonce 一次性存储（SEC-VIAM-DSN-CR-003 / D-VIAM-3-04 / FR-VIAM-3-4）
 * <p>
 * Redis {@code SET NX EX} 原子实现一次性消费：key 为 nonce 的 SHA-256 摘要（不落原文），
 * TTL 由配置给出（默认 2 分钟）。重复提交即判定重放。
 * <b>消费成功但后续校验失败时不回滚</b>（防重放优先）。
 * Redis 不可用时抛 {@link DeviceProofDependencyException}（fail-closed，不当作首次通过）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeviceProofNonceStore {

    static final String KEY_PREFIX = "viam:device-proof:nonce:";

    private final StringRedisTemplate stringRedisTemplate;
    private final DeviceProofProperties properties;

    /**
     * 一次性消费 nonce。
     *
     * @param nonce 调用方生成的 nonce 原文
     * @return true=首次消费成功；false=已消费（重放）
     * @throws DeviceProofDependencyException Redis 不可用
     */
    public boolean consume(String nonce) {
        if (nonce == null || nonce.isBlank()) {
            return false;
        }
        String key = KEY_PREFIX + ViamUtils.sha256Hex(nonce);
        try {
            Boolean first = stringRedisTemplate.opsForValue()
                    .setIfAbsent(key, "1", ttlSeconds(), TimeUnit.SECONDS);
            return Boolean.TRUE.equals(first);
        } catch (RuntimeException e) {
            throw new DeviceProofDependencyException("nonce一次性存储不可用: " + e.getClass().getSimpleName(), e);
        }
    }

    private long ttlSeconds() {
        Duration ttl = properties.getNonceTtl();
        long seconds = ttl == null ? 120L : ttl.toSeconds();
        return Math.max(1L, seconds);
    }
}
