package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationReason;
import net.hwyz.iov.cloud.sec.viam.api.constant.AccessInvalidationType;

import java.time.Instant;

/**
 * 访问失效执行跟踪记录（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * 保存可变的重试/回执状态：PENDING → ACKNOWLEDGED/TIMEOUT/RECONCILED/CANCELLED_STALE；
 * 回执区分 CACHE_ACL_INVALIDATED/DISCONNECTED/SESSION_NOT_FOUND/FAILED_RETRY/ACCEPTED。
 * effectiveBy 从安全状态提交时间（F）起算；超时触发告警/对账。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessInvalidationRecord {

    /** 主键（DB 自增） */
    private Long id;

    /** 失效请求ID（事件幂等键） */
    private String invalidationId;

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

    /** 触发时安全状态版本 */
    private long securityVersion;

    /** 绑定版本（换件/解绑时） */
    private Long bindingVersion;

    /** 目标会话 generation（仅 CONNECTION_DISPOSAL） */
    private Long targetGeneration;

    /** 生效起点 F */
    private Instant effectiveAt;

    /** 生效时限（F + effective-by-seconds） */
    private Instant effectiveBy;

    /** 执行状态：PENDING/ACKNOWLEDGED/TIMEOUT/RECONCILED/CANCELLED_STALE */
    private String status;

    /** 回执状态：CACHE_ACL_INVALIDATED/DISCONNECTED/SESSION_NOT_FOUND/FAILED_RETRY/ACCEPTED */
    private String receiptState;

    /** 回执明细 */
    private String receiptDetail;

    /** 执行结果扩展（非敏感） */
    private String executionResultJson;

    /** 事件 payload 摘要（幂等/一致性） */
    private String eventPayloadDigest;

    /** 重试次数 */
    private int retryCount;

    /** 最近重试时间 */
    private Instant lastRetryAt;

    /** 是否已触发超时告警 */
    private boolean timeoutAlerted;

    /** 执行状态常量 */
    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_ACKNOWLEDGED = "ACKNOWLEDGED";
    public static final String STATUS_TIMEOUT = "TIMEOUT";
    public static final String STATUS_RECONCILED = "RECONCILED";
    public static final String STATUS_CANCELLED_STALE = "CANCELLED_STALE";

    /** 回执状态常量 */
    public static final String RECEIPT_CACHE_ACL_INVALIDATED = "CACHE_ACL_INVALIDATED";
    public static final String RECEIPT_DISCONNECTED = "DISCONNECTED";
    public static final String RECEIPT_SESSION_NOT_FOUND = "SESSION_NOT_FOUND";
    public static final String RECEIPT_FAILED_RETRY = "FAILED_RETRY";
    public static final String RECEIPT_ACCEPTED = "ACCEPTED";
}
