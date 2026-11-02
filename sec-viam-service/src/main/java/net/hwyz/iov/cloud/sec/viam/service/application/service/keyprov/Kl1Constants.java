package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

/**
 * KEYPROV-LIFECYCLE-1（KL1）规范常量（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / T04）。
 * <p>
 * 本组常量为协议层固定值，仅允许由 PAR-PROTO KL1 基线统一调整；VIAM 不得单独改变默认。
 * 迁入自 VMD 既有实现（VMD-DSN-CR-069），语义保持。
 * </p>
 *
 * @author hwyz_leo
 */
public final class Kl1Constants {

    private Kl1Constants() {
    }

    /** KL1 profile 标识（批次 lifecycle_profile） */
    public static final String PROFILE = "KEYPROV-LIFECYCLE-1";

    /** 响应租约 TTL：E = min(server_now + 60s, B - 30s) */
    public static final long RESPONSE_TTL_MS = 60_000L;

    /** 批次 ACK 截止：B = F + 300s，不可滑动 */
    public static final long BATCH_MS = 300_000L;

    /** ACK 宽限：E = min(now + TTL, B - GRACE) */
    public static final long ACK_GRACE_MS = 30_000L;

    /** E - now < 20s → EXPIRED 无 items（不 SUCCEEDED） */
    public static final long ISSUE_MIN_MS = 20_000L;

    /** 设备导入准入：U < E 且 E - U ≥ 15s（TSP 侧 accept 用；VIAM 只签发 E） */
    public static final long IMPORT_MIN_MS = 15_000L;

    /** 服务端接收统计（非车端预算）：每 rid Request 参考上限 8 次 / 120s */
    public static final long REQUEST_LIMIT = 8L;
    public static final long REQUEST_WINDOW_MS = 120_000L;

    /** 服务端接收统计：每 rid ACK 参考上限 3 次 */
    public static final long ACK_LIMIT = 3L;

    /** 服务端接收统计：Status/SEC 只读参考上限 12 次 / 300s */
    public static final long READONLY_LIMIT = 12L;
    public static final long READONLY_WINDOW_MS = 300_000L;

    /** 不可变内容摘要域分隔：immutable_content_digest = SHA256(ASCII(domain) || 0x00 || C) */
    public static final String CONTENT_DIGEST_DOMAIN = "openiov|keyprov-content|kl1";

    /** Provider 处理中超过该秒数且副作用 unknown：只隔离告警 */
    public static final long PROVIDER_INFLIGHT_UNKNOWN_SECONDS = 120L;

    /** 终态治理原因 */
    public static final String TERMINAL_REASON_ACK_TIMEOUT = "ACK_TIMEOUT";
    public static final String TERMINAL_REASON_MIGRATION_QUARANTINE = "QUARANTINE_MIGRATION";

    /** 同 ID 内容冲突稳定错误 */
    public static final String ERR_CONTENT_CONFLICT = "KEYPROV_IDEMPOTENCY_CONFLICT";
}
