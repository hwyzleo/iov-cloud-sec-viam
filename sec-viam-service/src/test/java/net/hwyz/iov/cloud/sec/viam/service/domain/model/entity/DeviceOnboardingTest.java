package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 安全开通状态机单元测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-006 / T02）
 * <p>
 * 覆盖：PRE_ACTIVE→ACTIVATING→ACTIVE 推进、first 只写一次、last 单调 max、
 * 终态不复活、不跨级激活、封禁/恢复。
 * </p>
 *
 * @author hwyz_leo
 */
class DeviceOnboardingTest {

    private DeviceOnboarding newOnboarding() {
        return DeviceOnboarding.builder()
                .principalId("PR-001")
                .hsmUid("HSM-0001")
                .vin("VIN0000000000001")
                .state(DeviceOnboarding.OnboardingState.PRE_ACTIVE)
                .build();
    }

    @Test
    void recordSuccessfulLogin_migratesPreActiveToActivating() {
        DeviceOnboarding onboarding = newOnboarding();
        Instant t1 = Instant.parse("2026-11-01T10:00:00Z");
        boolean migrated = onboarding.recordSuccessfulLogin(t1);
        assertTrue(migrated);
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVATING, onboarding.getState());
        assertEquals(t1, onboarding.getFirstLoginTime());
        assertEquals(t1, onboarding.getLastLoginTime());
    }

    @Test
    void recordSuccessfulLogin_firstWrittenOnceLastMonotonicMax() {
        DeviceOnboarding onboarding = newOnboarding();
        Instant t1 = Instant.parse("2026-11-01T10:00:00Z");
        Instant t2 = Instant.parse("2026-11-01T11:00:00Z");
        Instant t3 = Instant.parse("2026-11-01T09:00:00Z"); // 迟到乱序事件
        onboarding.recordSuccessfulLogin(t1);
        onboarding.recordSuccessfulLogin(t2);
        onboarding.recordSuccessfulLogin(t3); // 迟到事件不得重置 first
        assertEquals(t1, onboarding.getFirstLoginTime());
        assertEquals(t2, onboarding.getLastLoginTime());
    }

    @Test
    void activate_onlyFromActivating() {
        DeviceOnboarding onboarding = newOnboarding();
        assertThrows(IllegalStateException.class, () -> onboarding.activate(1L));
        onboarding.recordSuccessfulLogin(Instant.now());
        onboarding.activate(1L);
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVE, onboarding.getState());
        assertEquals(1L, onboarding.getActivateVersion());
        // 终态不复活
        assertThrows(IllegalStateException.class, () -> onboarding.activate(2L));
    }

    @Test
    void blockAndUnblock_keepsLoginFacts() {
        DeviceOnboarding onboarding = newOnboarding();
        onboarding.recordSuccessfulLogin(Instant.parse("2026-11-01T10:00:00Z"));
        onboarding.block("CERT_REVOKED", Instant.parse("2026-11-02T00:00:00Z"));
        assertEquals(DeviceOnboarding.OnboardingState.BLOCKED, onboarding.getState());
        // 封禁后不再记录成功接入
        assertFalse(onboarding.recordSuccessfulLogin(Instant.parse("2026-11-02T08:00:00Z")));
        onboarding.unblock();
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVATING, onboarding.getState());
        assertEquals(Instant.parse("2026-11-01T10:00:00Z"), onboarding.getFirstLoginTime());
    }

    @Test
    void blockOnlyFromNonRetired() {
        DeviceOnboarding onboarding = newOnboarding();
        onboarding.block("SECURITY_ISOLATION", Instant.now());
        assertEquals(DeviceOnboarding.OnboardingState.BLOCKED, onboarding.getState());
        assertEquals("SECURITY_ISOLATION", onboarding.getBlockReason());
    }
}
