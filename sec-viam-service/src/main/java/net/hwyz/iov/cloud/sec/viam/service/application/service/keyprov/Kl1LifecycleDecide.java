package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import java.time.Instant;

/**
 * KEYPROV-LIFECYCLE-1（KL1）生产决策纯函数（迁入 VMD 既有实现，语义保持）。
 * <p>
 * TTL 签发、状态/错误矩阵、时间比较全部抽成纯函数：每个决策只依赖输入参数与固定常量，
 * 时间一律以参数传入（UTC epoch ms）。VMD 侧职责迁入 VIAM：
 * issue（租约签发）、ack（ACK 线性化）、dedupe（内容幂等）、store（重放存储 fail-closed）。
 * </p>
 *
 * @author hwyz_leo
 */
public final class Kl1LifecycleDecide {

    private Kl1LifecycleDecide() {
    }

    /** LC01/LC03/LC20 — 租约签发：E = min(now + 60s, B - 30s)；E-now < 20s → EXPIRED_NO_ITEMS。 */
    public static IssueDecision issue(long nowMs, long batchDeadlineMs, boolean safetyValidThroughE) {
        if (!safetyValidThroughE) {
            return IssueDecision.securityBlocked();
        }
        long e = Math.min(nowMs + Kl1Constants.RESPONSE_TTL_MS, batchDeadlineMs - Kl1Constants.ACK_GRACE_MS);
        if (e - nowMs < Kl1Constants.ISSUE_MIN_MS) {
            return IssueDecision.expiredNoItems();
        }
        return IssueDecision.freshResponse(e);
    }

    /** LC04/LC05/LC19 — ACK 线性化：锁内先判已有 ACTIVE（精确重复 proof 幂等），再判 B 到期。 */
    public static AckDecision ack(String state, long nowMs, long batchDeadlineMs,
                                  boolean validDualProof, boolean exactRepeat) {
        if ("ACTIVE".equals(state)) {
            // ACTIVE 快速路径必须重新鉴权并精确匹配持久化 ACK 身份/两用途 proof 摘要；错 proof 拒绝
            return AckDecision.active(exactRepeat);
        }
        if ("FAILED".equals(state) || nowMs >= batchDeadlineMs) {
            // 到期未激活 → FAILED(ACK_TIMEOUT)；FAILED 迟到 ACK 绝不复活
            return AckDecision.failedAckTimeout();
        }
        if (!validDualProof) {
            return AckDecision.rejectAck();
        }
        return AckDecision.activate();
    }

    /** LC07/LC08 — 同 rid 内容幂等：业务内容摘要相同 → 新鲜租约；不同 → 冲突，只读对账。 */
    public static DedupeDecision dedupe(boolean sameBusinessDigest) {
        return sameBusinessDigest ? DedupeDecision.sameBatchFreshLease() : DedupeDecision.conflict806095();
    }

    /** LC24 — 重放存储 fail-closed：digest 损坏/未知 codec/profile → 隔离，禁止重新 derive 补齐。 */
    public static StoreDecision store(boolean digestValid, boolean codecKnown, boolean profileKnown) {
        boolean ok = digestValid && codecKnown && profileKnown;
        return ok ? StoreDecision.replay() : StoreDecision.storeQuarantine();
    }

    // ---- 决策结果（纯数据） ----

    public static final class IssueDecision {
        private final String action;
        private final long expireAtMs;

        private IssueDecision(String action, long expireAtMs) {
            this.action = action;
            this.expireAtMs = expireAtMs;
        }

        public static IssueDecision freshResponse(long expireAtMs) {
            return new IssueDecision("FRESH_RESPONSE", expireAtMs);
        }

        public static IssueDecision expiredNoItems() {
            return new IssueDecision("EXPIRED_NO_ITEMS", 0L);
        }

        public static IssueDecision securityBlocked() {
            return new IssueDecision("SECURITY_BLOCKED", 0L);
        }

        public String action() {
            return action;
        }

        public long expireAtMs() {
            return expireAtMs;
        }
    }

    public static final class AckDecision {
        private final String action;
        private final boolean shouldActivate;

        private AckDecision(String action, boolean shouldActivate) {
            this.action = action;
            this.shouldActivate = shouldActivate;
        }

        public static AckDecision active(boolean exactRepeat) {
            return new AckDecision(exactRepeat ? "ACTIVE" : "REJECT_ACK", false);
        }

        public static AckDecision failedAckTimeout() {
            return new AckDecision("FAILED_ACK_TIMEOUT", false);
        }

        public static AckDecision rejectAck() {
            return new AckDecision("REJECT_ACK", false);
        }

        public static AckDecision activate() {
            return new AckDecision("ACTIVE", true);
        }

        public String action() {
            return action;
        }

        public boolean shouldActivate() {
            return shouldActivate;
        }
    }

    public static final class DedupeDecision {
        private final String action;

        private DedupeDecision(String action) {
            this.action = action;
        }

        public static DedupeDecision sameBatchFreshLease() {
            return new DedupeDecision("SAME_BATCH_FRESH_LEASE");
        }

        public static DedupeDecision conflict806095() {
            return new DedupeDecision("CONFLICT_806095");
        }

        public String action() {
            return action;
        }
    }

    public static final class StoreDecision {
        private final String action;

        private StoreDecision(String action) {
            this.action = action;
        }

        public static StoreDecision replay() {
            return new StoreDecision("REPLAY");
        }

        public static StoreDecision storeQuarantine() {
            return new StoreDecision("STORE_QUARANTINE");
        }

        public String action() {
            return action;
        }
    }

    /** 便捷：当前 UTC epoch ms（业务层注入，便于测试固定时间）。 */
    public static long nowMs(Instant now) {
        return now.toEpochMilli();
    }
}
