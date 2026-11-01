package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 设备业务密钥目录实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / D-VIAM-004）
 * <p>
 * 迁入 VmdBusinessKeyService 业务职能与目录版本语义：单 ACTIVE、业务版本单调递增、
 * DERIVED_ROOT/RANDOM_MATERIAL 分流、logicalKeyId、业务版本/根版本/派生版本。
 * 禁止保存明文密钥、完整 Wrapped Key、设备私钥或可恢复密钥材料。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceBusinessKey {

    /** 设备实例序列号快照 */
    private String deviceSn;

    /** 创建时 active vehicle_part.id */
    private Long bindingId;

    /** 设备物理实例，关联 part_info.id */
    private Long partId;

    /** 创建时权威安全芯片 UID 快照 */
    private String hsmUid;

    /** 受治理业务域代码 */
    private String businessDomain;

    /** 受治理用途代码 */
    private String purpose;

    /** 材料模型：DERIVED_ROOT/RANDOM_MATERIAL；历史 NULL 不猜测 */
    private String materialModel;

    /** framework/KMS 返回的不透明标识，唯一 */
    private String keyId;

    /** 业务版本，同上下文单调递增 */
    private long businessKeyVersion;

    /** KMS 引用，不是密钥本体 */
    private String kmsKeyRef;

    /** KMS/provider 内部版本 */
    private Integer kmsKeyVersion;

    /** KMS 提供方 */
    private String kmsProvider;

    /** Transit/HSM 根版本（仅根派生型） */
    private Long rootKeyVersion;

    /** 派生格式版本（首期 v1） */
    private String derivationVersion;

    /** 算法快照 */
    private String algorithm;

    /** 密钥规格快照 */
    private String keySpec;

    /** 密钥状态 */
    private KeyState keyState;

    /** 有效窗口开始 */
    private Instant validFrom;

    /** 有效窗口结束 */
    private Instant validTo;

    /** DEPRECATED 仅解密截止时间 */
    private Instant decryptUntil;

    /** 封装模式（首期固定 DEVICE_CERT_PUBLIC_KEY） */
    private String wrapMode;

    /** 最近设备封装使用的证书序列号（仅审计） */
    private String lastRecipientCertSn;

    /** 调用幂等键 */
    private String requestId;

    /** 根派生操作标识（对账主键） */
    private String operationId;

    /** 被取代后指向 canonical 目录行 */
    private Long supersededById;

    /** 非敏感规范化身份摘要 */
    private byte[] logicalIdentityDigest;

    /** 同目录材料恢复次数 */
    private int recoveryCount;

    /** 最近恢复 attempt 审计引用 */
    private String lastRecoveryRequestId;

    /** 规范化请求摘要 */
    private String requestDigest;

    /** 创建时授权/密码学策略版本 */
    private String policyVersion;

    /** 最近失败原因 */
    private String failReason;

    /** 最近尝试时间 */
    private Instant lastAttemptTime;

    /** 密钥状态 */
    public enum KeyState {
        PENDING, ACTIVE, DEPRECATED, REVOKING, REVOKED, EXPIRED,
        FAILED, RECONCILE_REQUIRED, PENDING_RECOVERY
    }

    /**
     * 激活：PENDING → ACTIVE。
     */
    public void activate() {
        if (keyState == KeyState.PENDING) {
            this.keyState = KeyState.ACTIVE;
        }
    }

    /**
     * 吊销：ACTIVE/DEPRECATED → REVOKED。
     */
    public void revoke() {
        if (keyState != KeyState.ACTIVE && keyState != KeyState.DEPRECATED) {
            throw new IllegalStateException("仅ACTIVE/DEPRECATED可吊销: " + keyState);
        }
        this.keyState = KeyState.REVOKED;
    }

    /**
     * 轮换：将当前 ACTIVE 转 DEPRECATED（旧材料仅解密窗口内可用）。
     */
    public void deprecateForRotation(Instant decryptUntil) {
        if (keyState != KeyState.ACTIVE) {
            throw new IllegalStateException("仅ACTIVE可轮换降级: " + keyState);
        }
        this.keyState = KeyState.DEPRECATED;
        this.decryptUntil = decryptUntil;
    }

    /**
     * 失败重试恢复计数：FAILED → PENDING_RECOVERY。
     */
    public void markPendingRecovery(String attemptRequestId) {
        this.keyState = KeyState.PENDING_RECOVERY;
        this.recoveryCount++;
        this.lastRecoveryRequestId = attemptRequestId;
    }
}
