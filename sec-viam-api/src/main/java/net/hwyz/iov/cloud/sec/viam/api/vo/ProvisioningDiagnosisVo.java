package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * 业务密钥阻塞诊断VO（SEC-VIAM-DSN-CR-002 / D-VIAM-017 / D-VIAM-018）
 * <p>
 * 只读诊断：标注阻塞层级（目录行级 / 批次级 / 无）、证据时间窗口与非敏感原因；
 * 不输出密钥材料、密文、信封字节与 digest 原始字节。诊断不改变任何状态。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningDiagnosisVo {

    /** 批次 requestId */
    private String requestId;

    /** 设备SN */
    private String deviceSn;

    /** 业务域 */
    private String businessDomain;

    /** 批次状态 */
    private String status;

    /** 阻塞层级：LOCAL_DIRECTORY / BATCH / NONE */
    private String blockingLevel;

    /** 阻塞原因（非敏感） */
    private String blockingReason;

    /** 当前状态是否允许清阻断（只读判断，不作为执行依据） */
    private Boolean clearable;

    /** KL1 标识（NULL 表示存量未迁移） */
    private String lifecycleProfile;

    /** KL1 F */
    private Instant firstIssuedAt;

    /** KL1 B */
    private Instant ackDeadlineAt;

    /** 当前最大租约序号 */
    private Integer leaseSeq;

    /** 最近租约过期时间 */
    private Instant leaseExpireAt;

    /** 终态治理原因 */
    private String terminalReason;

    /** 逐用途明细（含目录行状态） */
    private List<ProvisioningItemVo> items;

    /** 诊断依据说明（非敏感，供运维理解判定路径） */
    private List<String> evidence;
}
