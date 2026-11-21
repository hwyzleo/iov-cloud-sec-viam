package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 设备证明校验限流单元测试（SEC-VIAM-DSN-CR-003 / TC-VIAM-3-06）。
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DeviceProofRateLimiterTest {

    private static final Instant NOW = Instant.parse("2026-11-20T10:00:00Z");

    @Mock
    private StringRedisTemplate stringRedisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private DeviceProofRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        DeviceProofProperties properties = new DeviceProofProperties();
        properties.getRateLimit().setPerCallerPerMinute(2);
        properties.getRateLimit().setPerDevicePerMinute(1);
        rateLimiter = new DeviceProofRateLimiter(stringRedisTemplate, properties);
        lenient().when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        lenient().when(stringRedisTemplate.expire(anyString(), anyLong(), any(TimeUnit.class))).thenReturn(true);
    }

    @Test
    @DisplayName("调用方维度超限 → 拒绝")
    void callerLimitExceeded() {
        when(valueOperations.increment(anyString())).thenReturn(1L, 2L, 3L);

        assertTrue(rateLimiter.tryAcquire("CIAM", null, NOW));
        assertTrue(rateLimiter.tryAcquire("CIAM", null, NOW));
        assertFalse(rateLimiter.tryAcquire("CIAM", null, NOW));
    }

    @Test
    @DisplayName("设备维度超限 → 拒绝（独立于调用方额度）")
    void deviceLimitExceeded() {
        when(valueOperations.increment(anyString())).thenReturn(1L, 1L, 2L);

        assertTrue(rateLimiter.tryAcquire("CIAM", "SN-1", NOW));
        assertFalse(rateLimiter.tryAcquire("CIAM", "SN-1", NOW));
    }

    @Test
    @DisplayName("首次计数设置窗口过期时间")
    void firstCountSetsExpiry() {
        when(valueOperations.increment(anyString())).thenReturn(1L);

        assertTrue(rateLimiter.tryAcquire("CIAM", null, NOW));

        verify(stringRedisTemplate).expire(anyString(), anyLong(), any(TimeUnit.class));
    }

    @Test
    @DisplayName("Redis 不可用 → DeviceProofDependencyException（fail-closed）")
    void redisUnavailableFailClosed() {
        when(valueOperations.increment(anyString())).thenThrow(new RedisConnectionFailureException("down"));

        assertThrows(DeviceProofDependencyException.class, () -> rateLimiter.tryAcquire("CIAM", null, NOW));
    }
}
