package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * 设备证明校验可观测性（SEC-VIAM-DSN-CR-003 §13.6）
 * <p>
 * 只在存在 {@link MeterRegistry}（actuator 自动装配）时打点，未引入时不阻塞业务。
 * 指标：校验成功/失败（按原因码）、nonce 重放计数、限流命中、校验耗时。
 * 不记录任何证明/证书内容。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class DeviceProofMetrics {

    static final String VERIFY_METRIC = "viam.device.proof.verify";
    static final String REPLAY_METRIC = "viam.device.proof.nonce.replay";
    static final String RATE_LIMITED_METRIC = "viam.device.proof.rate.limited";

    private final ObjectProvider<MeterRegistry> registryProvider;

    public DeviceProofMetrics(ObjectProvider<MeterRegistry> registryProvider) {
        this.registryProvider = registryProvider;
    }

    /**
     * 记录一次校验结论与耗时。
     */
    public void recordVerify(String reasonCode, boolean valid, Duration elapsed) {
        MeterRegistry registry = registryProvider.getIfAvailable();
        if (registry == null) {
            return;
        }
        try {
            registry.counter(VERIFY_METRIC,
                    "result", valid ? "VALID" : "REJECTED",
                    "reason", reasonCode == null ? "UNKNOWN" : reasonCode).increment();
            if (elapsed != null) {
                registry.timer(VERIFY_METRIC + ".duration",
                        "reason", reasonCode == null ? "UNKNOWN" : reasonCode)
                        .record(elapsed.toNanos(), TimeUnit.NANOSECONDS);
            }
        } catch (RuntimeException e) {
            log.debug("设备证明指标记录失败（忽略）: {}", e.getMessage());
        }
    }

    /**
     * nonce 重放计数。
     */
    public void recordNonceReplay() {
        increment(REPLAY_METRIC);
    }

    /**
     * 限流命中计数。
     */
    public void recordRateLimited() {
        increment(RATE_LIMITED_METRIC);
    }

    private void increment(String metric) {
        MeterRegistry registry = registryProvider.getIfAvailable();
        if (registry == null) {
            return;
        }
        try {
            registry.counter(metric).increment();
        } catch (RuntimeException e) {
            log.debug("设备证明指标记录失败（忽略）: {}", e.getMessage());
        }
    }
}
