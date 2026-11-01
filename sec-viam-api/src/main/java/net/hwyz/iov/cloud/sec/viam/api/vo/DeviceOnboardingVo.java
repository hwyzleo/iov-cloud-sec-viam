package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 设备安全开通状态VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-006）
 * <p>
 * 承接 PRE_ACTIVE→ACTIVATING→ACTIVE 安全开通流程：建链成功进入 ACTIVATING，
 * 完整两用途密钥 ACK 确认后 ACTIVE。安全阻断/退役状态独立于 TSP 运营状态。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceOnboardingVo {

    /** 安全主体ID */
    private String principalId;

    /** 归一化 HSM UID */
    private String hsmUid;

    /** 车辆VIN */
    private String vin;

    /** 安全开通状态：PRE_ACTIVE / ACTIVATING / ACTIVE / BLOCKED / RETIRED */
    private String state;

    /** 首次可信成功接入时间 */
    private Instant firstLoginTime;

    /** 最近可信成功接入时间 */
    private Instant lastLoginTime;

    /** 历史 ACTIVE/activateTime legacy 语义（保留原值，不伪称新验签已完成） */
    private Instant legacyActiveTime;

    /** 安全封禁原因（可解释 reason） */
    private String blockReason;

    /** 安全封禁生效时限 */
    private Instant blockEffectiveAt;
}
