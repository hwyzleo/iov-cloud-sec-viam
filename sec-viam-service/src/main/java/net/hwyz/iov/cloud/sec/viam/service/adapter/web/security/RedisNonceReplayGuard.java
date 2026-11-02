package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import net.hwyz.iov.cloud.framework.redis.service.RedisService;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Redis 原子 nonce 重放防护（G-4）。
 * <p>
 * 使用 {@code setIfAbsent} 原子占用 {@code viam:nonce:<clientId>:<nonce>}，
 * 保留时长 = 时间戳窗口 + 安全余量，防重放。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
public class RedisNonceReplayGuard implements NonceReplayGuard {

    private static final String KEY_PREFIX = "viam:nonce:";

    private final RedisService redisService;

    public RedisNonceReplayGuard(RedisService redisService) {
        this.redisService = redisService;
    }

    @Override
    public boolean tryClaim(String clientId, String nonce, long ttlSeconds) {
        String key = KEY_PREFIX + clientId + ":" + nonce;
        Boolean claimed = redisService.redisTemplate.opsForValue()
                .setIfAbsent(key, "1", ttlSeconds + 60, TimeUnit.SECONDS);
        return Boolean.TRUE.equals(claimed);
    }
}
