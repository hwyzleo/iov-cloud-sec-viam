package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 准入裁决审计实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-005 / D-VIAM-007）
 * <p>
 * 以决策时刻 decisionAt 记录；成功接入以 actual connected occurredAt 为准。
 * 本记录同时是成功接入证据的来源（admissionDecisionId 关联）。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DecisionAudit {

    /** 准入裁决ID（幂等键/证据关联） */
    private String admissionDecisionId;

    /** 裁决结果：ALLOW/DENY */
    private String decision;

    /** 语义裁决原因 */
    private String reason;

    /** UID 摘要（审计禁明文） */
    private String uidDigest;

    /** 证书序列号摘要 */
    private String certSerialDigest;

    /** 来源IP摘要 */
    private String sourceIpDigest;

    /** VIN（ALLOW 时） */
    private String vin;

    /** 绑定状态 */
    private String bindStatus;

    /** 证书状态 */
    private String certStatus;

    /** 设备安全开通准入态 */
    private String deviceStatus;

    /** 绑定版本 */
    private Long bindVersion;

    /** 不可变准入快照摘要（成功接入证据） */
    private String snapshotDigest;

    /** 准入快照有效期 */
    private Instant snapshotExpiresAt;

    /** 调用方标识 */
    private String caller;

    /** 依赖结果分类 */
    private String dependencyOutcome;

    /** PKI 查询耗时 */
    private Long pkiLatencyMs;

    /** 裁决耗时 */
    private Long responseTimeMs;

    /** 裁决时间（UTC Instant） */
    private Instant decisionAt;
}
