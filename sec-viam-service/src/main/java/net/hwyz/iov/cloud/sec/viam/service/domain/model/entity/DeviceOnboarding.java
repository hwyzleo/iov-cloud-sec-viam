package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 设备安全开通状态实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-006 / D-VIAM-008）
 * <p>
 * 承接 PRE_ACTIVE→ACTIVATING→ACTIVE 安全开通流程：建链成功进入 ACTIVATING，
 * 完整两用途密钥 ACK 确认后 ACTIVE。安全阻断/退役状态独立于 TSP 运营状态；
 * first 只写一次、last 单调 max；终态不复活、不跨级激活。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceOnboarding {

    /** 安全主体ID */
    private String principalId;

    /** 归一化 HSM UID */
    private String hsmUid;

    /** 车辆VIN */
    private String vin;

    /** 设备序列号 */
    private String deviceSn;

    /** 安全开通状态 */
    private OnboardingState state;

    /** 首次可信成功接入时间（只写一次） */
    private Instant firstLoginTime;

    /** 最近可信成功接入时间（单调 max） */
    private Instant lastLoginTime;

    /** 历史 ACTIVE 时间（legacy 语义，不伪称新验签已完成） */
    private Instant legacyActiveTime;

    /** 安全封禁原因 */
    private String blockReason;

    /** 封禁生效时限 */
    private Instant blockEffectiveAt;

    /** 激活推进版本（幂等/乱序收敛） */
    private long activateVersion;

    /** 安全开通状态 */
    public enum OnboardingState {
        PRE_ACTIVE, ACTIVATING, ACTIVE, BLOCKED, RETIRED
    }

    /**
     * 可信成功接入推进：PRE_ACTIVE → ACTIVATING；first 只写一次，last 单调 max。
     *
     * @param occurredAt 实际接入时间
     * @return 是否发生状态迁移（PRE_ACTIVE→ACTIVATING）
     */
    public boolean recordSuccessfulLogin(Instant occurredAt) {
        if (state == OnboardingState.BLOCKED || state == OnboardingState.RETIRED) {
            return false;
        }
        if (firstLoginTime == null) {
            this.firstLoginTime = occurredAt;
        }
        if (lastLoginTime == null || occurredAt.isAfter(lastLoginTime)) {
            this.lastLoginTime = occurredAt;
        }
        boolean migrated = false;
        if (state == OnboardingState.PRE_ACTIVE) {
            this.state = OnboardingState.ACTIVATING;
            migrated = true;
        }
        return migrated;
    }

    /**
     * 完整用途集 ACK 确认后激活：仅 ACTIVATING 可推进 ACTIVE（不跨级激活）。
     */
    public void activate(long expectedVersion) {
        if (state != OnboardingState.ACTIVATING) {
            throw new IllegalStateException("仅ACTIVATING可激活，当前=" + state);
        }
        if (activateVersion > expectedVersion) {
            throw new IllegalStateException("激活版本回退，拒绝跨级推进");
        }
        this.state = OnboardingState.ACTIVE;
        this.activateVersion = expectedVersion;
    }

    /**
     * 安全封禁：ACTIVE/ACTIVATING/PRE_ACTIVE → BLOCKED。
     */
    public void block(String reason, Instant effectiveAt) {
        if (state == OnboardingState.RETIRED) {
            throw new IllegalStateException("已退役不可封禁");
        }
        this.state = OnboardingState.BLOCKED;
        this.blockReason = reason;
        this.blockEffectiveAt = effectiveAt;
    }

    /**
     * 恢复：BLOCKED → ACTIVATING（保留既有登录事实）。
     */
    public void unblock() {
        if (state != OnboardingState.BLOCKED) {
            throw new IllegalStateException("仅封禁可恢复");
        }
        this.state = lastLoginTime != null ? OnboardingState.ACTIVATING : OnboardingState.PRE_ACTIVE;
        this.blockReason = null;
        this.blockEffectiveAt = null;
    }
}
