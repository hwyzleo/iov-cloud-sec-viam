package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * 设备证明校验限流（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-7）
 * <p>
 * 按「调用方服务身份 + 设备维度」做固定窗口计数（Redis INCR + 首次 EXPIRE 60s），
 * 防止证明爆破。key 只含摘要，不落调用方原文之外的设备标识。
 * Redis 不可用时抛 {@link DeviceProofDependencyException}（fail-closed）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeviceProofRateLimiter {

    static final String CALLER_KEY_PREFIX = "viam:device-proof:rate:caller:";
    static final String DEVICE_KEY_PREFIX = "viam:device-proof:rate:device:";
    private static final long WINDOW_SECONDS = 60L;

    private final StringRedisTemplate stringRedisTemplate;
    private final DeviceProofProperties properties;

    /**
     * 限流检查。
     *
     * @param caller   调用方服务身份（缺失时为 UNKNOWN）
     * @param deviceId 设备标识线索（可空；空则只做调用方维度）
     * @param at       校验时刻
     * @return true=允许；false=超限
     * @throws DeviceProofDependencyException Redis 不可用
     */
    public boolean tryAcquire(String caller, String deviceId, Instant at) {
        long window = (at == null ? Instant.now() : at).getEpochSecond() / WINDOW_SECONDS;
        DeviceProofProperties.RateLimit limit = properties.getRateLimit();
        String callerKey = CALLER_KEY_PREFIX + normalize(caller) + ":" + window;
        int callerLimit = limit == null ? 60 : limit.getPerCallerPerMinute();
        if (increment(callerKey) > callerLimit) {
            return false;
        }
        if (deviceId == null || deviceId.isBlank()) {
            return true;
        }
        String deviceKey = DEVICE_KEY_PREFIX + ViamUtils.sha256Hex(deviceId.trim()) + ":" + window;
        int deviceLimit = limit == null ? 12 : limit.getPerDevicePerMinute();
        return increment(deviceKey) <= deviceLimit;
    }

    private long increment(String key) {
        try {
            Long count = stringRedisTemplate.opsForValue().increment(key);
            if (count != null && count == 1L) {
                stringRedisTemplate.expire(key, WINDOW_SECONDS, TimeUnit.SECONDS);
            }
            return count == null ? 0L : count;
        } catch (RuntimeException e) {
            throw new DeviceProofDependencyException("限流依赖不可用: " + e.getClass().getSimpleName(), e);
        }
    }

    private static String normalize(String caller) {
        if (caller == null || caller.isBlank()) {
            return "UNKNOWN";
        }
        return caller.trim().replace(":", "_");
    }
}
