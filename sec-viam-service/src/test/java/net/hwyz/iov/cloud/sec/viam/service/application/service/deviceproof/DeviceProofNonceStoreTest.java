package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * nonce 一次性存储单元测试（SEC-VIAM-DSN-CR-003 / TC-VIAM-3-03）。
 * <p>
 * SET NX + TTL 原子消费；key 只存 nonce 摘要；Redis 不可用 fail-closed。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DeviceProofNonceStoreTest {

    private static final String NONCE = "nonce-0123456789abcdef";

    @Mock
    private StringRedisTemplate stringRedisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private DeviceProofNonceStore nonceStore;

    @BeforeEach
    void setUp() {
        DeviceProofProperties properties = new DeviceProofProperties();
        properties.setNonceTtl(Duration.ofMinutes(2));
        nonceStore = new DeviceProofNonceStore(stringRedisTemplate, properties);
    }

    @Test
    @DisplayName("首次消费成功，重复消费失败（重放）")
    void firstConsumeSucceedsAndReplayFails() {
        when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class)))
                .thenReturn(true, false);

        assertTrue(nonceStore.consume(NONCE));
        assertFalse(nonceStore.consume(NONCE));

        // key 只含摘要，不落 nonce 原文
        verify(valueOperations, org.mockito.Mockito.times(2)).setIfAbsent(
                eq(DeviceProofNonceStore.KEY_PREFIX + ViamUtils.sha256Hex(NONCE)),
                anyString(), eq(120L), any(TimeUnit.class));
    }

    @Test
    @DisplayName("Redis 不可用 → DeviceProofDependencyException（fail-closed）")
    void redisUnavailableFailClosed() {
        when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class)))
                .thenThrow(new RedisConnectionFailureException("down"));

        assertThrows(DeviceProofDependencyException.class, () -> nonceStore.consume(NONCE));
    }

    @Test
    @DisplayName("空 nonce 视为消费失败（不建立键）")
    void blankNonceIsNotConsumed() {
        assertFalse(nonceStore.consume(" "));
    }
}
