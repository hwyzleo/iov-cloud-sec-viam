package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

/**
 * 业务密钥开通批次实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / D-VIAM-004）
 * <p>
 * 迁入 VmdKeyProvisioningService 业务职能与批次/item/租约语义：
 * 批次 requestId 幂等、KL1 固定 F/B、终态不复活、同 requestId 幂等、
 * 冻结响应/operation 证据、结果未知恢复。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningBatch {

    /** 主键（DB 自增；插入后回填） */
    private Long id;

    /** TBOX 稳定 requestId（批次幂等键） */
    private String requestId;

    /** 规范化请求摘要 */
    private String requestDigest;

    /** 规范化 ACK 摘要；未确认时为空 */
    private String ackDigest;

    /** TBOX 序列号 */
    private String deviceSn;

    /** 发起时 active vehicle_part.id 快照 */
    private Long bindingId;

    /** 设备物理实例，关联 part_info.id */
    private Long partId;

    /** HSM UID 摘要 */
    private String hsmUidDigest;

    /** 设备证书序列号摘要 */
    private String certificateSnDigest;

    /** 业务域；首期固定 V2C_COMM */
    private String businessDomain;

    /** 批次状态 */
    private BatchState status;

    /** 非敏感失败原因 */
    private String failReason;

    /** 响应证据（加密 BLOB 或受控引用；重放不更新） */
    private byte[] responsePayload;
    private String responseRef;
    private String responseDigest;
    private String responseCodecVersion;
    private Instant responsePersistedAt;

    /** KL1 生命周期 */
    private String lifecycleProfile;
    private Instant firstIssuedAt;
    private Instant ackDeadlineAt;
    private String immutableContentDigest;
    private Integer leaseSeq;
    private String terminalReason;
    private Instant terminalAt;

    /** 开通时间 */
    private Instant startedAt;
    private Instant acknowledgedAt;
    private Instant completedAt;

    /** 逐用途明细 */
    private List<ProvisioningItem> items;

    /** 批次状态 */
    public enum BatchState {
        PREPARING, WAIT_DEVICE_ACK, COMPLETED, FAILED, RECONCILE_REQUIRED, EXPIRED
    }

    /**
     * KL1 首次完整响应原子持久化（F 不可滑动；重放不延 B）。
     *
     * @param ackDeadlineSeconds ACK 截止 = F + 固定秒数
     */
    public void freezeFirstIssuance(byte[] response, String digest, long ackDeadlineSeconds) {
        if (firstIssuedAt != null) {
            throw new IllegalStateException("KL1 F 已固化，禁止重写首次持久化时间");
        }
        this.responsePayload = response;
        this.responseDigest = digest;
        this.responsePersistedAt = Instant.now();
        this.firstIssuedAt = Instant.now();
        this.ackDeadlineAt = this.firstIssuedAt.plusSeconds(ackDeadlineSeconds);
        this.lifecycleProfile = "KEYPROV-LIFECYCLE-1";
        this.leaseSeq = 0;
        this.status = BatchState.WAIT_DEVICE_ACK;
    }

    /**
     * ACK 到达（真实验签后）：校验截止时间与终态，推进 COMPLETED。
     */
    public void acknowledge(String ackDigest, Instant ackAt, boolean fullPurposeSetAcked) {
        if (status == BatchState.COMPLETED) {
            throw new IllegalStateException("批次已COMPLETED，终态不复活");
        }
        if (status == BatchState.FAILED || status == BatchState.EXPIRED) {
            throw new IllegalStateException("批次已终态，不得复活: " + status);
        }
        if (ackDeadlineAt != null && ackAt.isAfter(ackDeadlineAt)) {
            throw new IllegalStateException("ACK超过固定截止时间（KL1 B）");
        }
        if (!fullPurposeSetAcked) {
            throw new IllegalStateException("完整用途集未全部ACK确认");
        }
        this.ackDigest = ackDigest;
        this.acknowledgedAt = ackAt;
        this.status = BatchState.COMPLETED;
        this.completedAt = ackAt;
    }

    /**
     * ACK 超时（B 到期）：终态治理 ACK_TIMEOUT。
     */
    public void expireByAckTimeout(Instant at) {
        if (status != BatchState.WAIT_DEVICE_ACK && status != BatchState.PREPARING
                && status != BatchState.RECONCILE_REQUIRED) {
            throw new IllegalStateException("当前状态不可ACK超时终态化: " + status);
        }
        this.status = BatchState.EXPIRED;
        this.terminalReason = "ACK_TIMEOUT";
        this.terminalAt = at;
    }

    /**
     * 结果未知（Provider 调用结果未知）：RECONCILE_REQUIRED，禁止自动重放。
     */
    public void markReconcileRequired(String reason) {
        if (status == BatchState.COMPLETED || status == BatchState.EXPIRED || status == BatchState.FAILED) {
            throw new IllegalStateException("终态不得转对账: " + status);
        }
        this.status = BatchState.RECONCILE_REQUIRED;
        this.failReason = reason;
    }
}
