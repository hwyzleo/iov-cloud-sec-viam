package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存 nonce 重放防护（仅隔离测试/无 Redis 环境；生产必须使用 Redis 实现）。
 * <p>
 * 生产默认装配 {@link RedisNonceReplayGuard}；本实现仅在 Redis 模板缺失时兜底，
 * 且单进程内有效，不作为多实例生产语义。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
@ConditionalOnMissingBean(RedisNonceReplayGuard.class)
public class InMemoryNonceReplayGuard implements NonceReplayGuard {

    private final Map<String, Long> claimed = new ConcurrentHashMap<>();

    @Override
    public boolean tryClaim(String clientId, String nonce, long ttlSeconds) {
        String key = clientId + ":" + nonce;
        long now = System.currentTimeMillis();
        Long previous = claimed.putIfAbsent(key, now + ttlSeconds * 1000L);
        if (previous != null) {
            return false;
        }
        // 惰性清理过期键
        claimed.entrySet().removeIf(e -> e.getValue() < now);
        return true;
    }
}
