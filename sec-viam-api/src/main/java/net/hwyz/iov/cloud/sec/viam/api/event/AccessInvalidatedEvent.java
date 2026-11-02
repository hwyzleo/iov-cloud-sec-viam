package net.hwyz.iov.cloud.sec.viam.api.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationReason;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationType;

import java.time.Instant;

/**
 * 访问失效触发事件（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * 对应待登记 Topic {@code viam.access-invalidated}（schema/owner/ACL 登记后方可启用）。
 * 双语义：
 * <ul>
 *   <li>CONNECTION_DISPOSAL：携带 targetGeneration，VAGW 仅处置指定会话，不得误断更新的合法会话；</li>
 *   <li>PRINCIPAL_REVOCATION：携带 securityVersion/bindingVersion/scope/reason，不因重连换 generation
 *       逃逸；VAGW 按当前安全版本/凭据/绑定判定仍不被允许的会话，清缓存/ACL 并实际断连。</li>
 * </ul>
 * effectiveBy 生效时限从安全状态提交时间（F）起算，不是事件消费时重新起算。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessInvalidatedEvent {

    /** 事件类型（契约稳定值） */
    public static final String EVENT_TYPE = "ACCESS_INVALIDATED";

    /** 事件唯一ID（幂等键） */
    private String eventId;

    /** 安全主体ID */
    private String principalId;

    /** 归一化 HSM UID */
    private String hsmUid;

    /** 车辆VIN */
    private String vin;

    /** 设备序列号 */
    private String deviceSn;

    /** 失效类型 */
    private AccessInvalidationType invalidationType;

    /** 失效原因 */
    private AccessInvalidationReason reason;

    /** 适用范围（PRINCIPAL/CREDENTIAL/BINDING/SESSION） */
    private String scope;

    /** 触发时安全状态版本（单调递增；乱序旧事件按版本判定不误断新会话） */
    private long securityVersion;

    /** 绑定版本（换件/解绑时） */
    private Long bindingVersion;

    /** 目标会话 generation（仅 CONNECTION_DISPOSAL；null=不限定） */
    private Long targetGeneration;

    /** 生效起点（安全状态事务提交时间 F） */
    private Instant effectiveAt;

    /** 生效时限（F + effective-by-seconds；当前开发目标 30s，非已验证生产 SLA） */
    private Instant effectiveBy;

    /** 触发来源（MPT_ADMIN/VAGW/OAPI_MES） */
    private String source;

    /** 操作人（EIAM 用户或受信 workload） */
    private String operatorId;
}
