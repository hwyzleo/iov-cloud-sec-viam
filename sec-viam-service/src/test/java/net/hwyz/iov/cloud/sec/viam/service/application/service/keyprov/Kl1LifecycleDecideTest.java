package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KL1 生命周期决策纯函数单元测试（SEC-VIAM-DSN-CR-001 / G-2）
 *
 * @author hwyz_leo
 */
class Kl1LifecycleDecideTest {

    private static final long NOW = 1_700_000_000_000L;
    private static final long B = NOW + Kl1Constants.BATCH_MS;

    @Test
    void issueComputesEWithinBounds() {
        Kl1LifecycleDecide.IssueDecision d = Kl1LifecycleDecide.issue(NOW, B, true);
        assertEquals("FRESH_RESPONSE", d.action());
        // E = min(now+60s, B-30s)；60s < 270s → E = now + 60s
        assertEquals(NOW + Kl1Constants.RESPONSE_TTL_MS, d.expireAtMs());
    }

    @Test
    void issueExpiredWhenHeadroomBelowMinimum() {
        // 距 B 不足 20s + 30s 宽限 → E-now < 20s
        long deadline = NOW + Kl1Constants.ACK_GRACE_MS + Kl1Constants.ISSUE_MIN_MS - 5_000L;
        Kl1LifecycleDecide.IssueDecision d = Kl1LifecycleDecide.issue(NOW, deadline, true);
        assertEquals("EXPIRED_NO_ITEMS", d.action());
    }

    @Test
    void issueSecurityBlockedStopsDelivery() {
        Kl1LifecycleDecide.IssueDecision d = Kl1LifecycleDecide.issue(NOW, B, false);
        assertEquals("SECURITY_BLOCKED", d.action());
    }

    @Test
    void ackActiveExactRepeatIdempotent() {
        // ACTIVE + 精确重复 proof → 幂等（不重复激活）
        Kl1LifecycleDecide.AckDecision d = Kl1LifecycleDecide.ack("ACTIVE", NOW, B, true, true);
        assertEquals("ACTIVE", d.action());
        assertFalse(d.shouldActivate());
    }

    @Test
    void ackActiveWrongProofRejected() {
        Kl1LifecycleDecide.AckDecision d = Kl1LifecycleDecide.ack("ACTIVE", NOW, B, true, false);
        assertEquals("REJECT_ACK", d.action());
    }

    @Test
    void ackTimeoutNoRevive() {
        // 到期未激活 → FAILED(ACK_TIMEOUT)，FAILED 迟到 ACK 绝不复活
        Kl1LifecycleDecide.AckDecision late = Kl1LifecycleDecide.ack("WAIT_DEVICE_ACK", B + 1, B, true, false);
        assertEquals("FAILED_ACK_TIMEOUT", late.action());
        Kl1LifecycleDecide.AckDecision failed = Kl1LifecycleDecide.ack("FAILED", NOW, B, true, false);
        assertEquals("FAILED_ACK_TIMEOUT", failed.action());
    }

    @Test
    void ackValidDualProofActivates() {
        Kl1LifecycleDecide.AckDecision d = Kl1LifecycleDecide.ack("WAIT_DEVICE_ACK", NOW, B, true, false);
        assertEquals("ACTIVE", d.action());
        assertTrue(d.shouldActivate());
    }

    @Test
    void ackInvalidProofRejected() {
        Kl1LifecycleDecide.AckDecision d = Kl1LifecycleDecide.ack("WAIT_DEVICE_ACK", NOW, B, false, false);
        assertEquals("REJECT_ACK", d.action());
    }

    @Test
    void dedupeAndStoreDecisions() {
        assertEquals("SAME_BATCH_FRESH_LEASE", Kl1LifecycleDecide.dedupe(true).action());
        assertEquals("CONFLICT_806095", Kl1LifecycleDecide.dedupe(false).action());
        assertEquals("REPLAY", Kl1LifecycleDecide.store(true, true, true).action());
        assertEquals("STORE_QUARANTINE", Kl1LifecycleDecide.store(false, true, true).action());
    }
}
