package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 业务密钥开通批次明细实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / D-VIAM-004）
 * <p>
 * 逐用途 ACK 明细；不落 wrapped_key/parameters 原文；保留 core/wire 双摘要与
 * 原响应无损切片证据。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningItem {

    /** 主键（DB 自增；插入后回填） */
    private Long id;

    /** 批次外键 */
    private Long provisioningId;

    /** 用途（UPLINK_AEAD / DOWNLINK_AEAD） */
    private String purpose;

    /** 对应 device_business_key.key_id */
    private String keyId;

    /** 业务版本 */
    private Long businessKeyVersion;

    /** device_business_key.id */
    private Long directoryKeyId;

    /** 根派生操作标识（对账主键） */
    private String operationId;

    /** Transit/HSM 根版本 */
    private Long rootKeyVersion;

    /** 派生格式版本 */
    private String derivationVersion;

    /** 收件设备证书指纹摘要 */
    private String recipientCertFingerprintDigest;

    /** 信封格式（首期 ECDH_ES_P256_V1） */
    private String envelopeFormat;

    /** 封装套件（allowlist） */
    private String wrappingSuite;

    /** FW-SEC core 内部完整性摘要 */
    private byte[] coreEnvelopeDigest;

    /** PAR-PROTO 9 字段 wire 摘要（权威） */
    private byte[] wireEnvelopeDigest;

    /** AAD profile（固定 PAR_PROTO_KEYPROV_AAD_V1） */
    private String aadProfileId;

    /** deterministic parameters 字节摘要 */
    private byte[] parametersDigest;

    /** wrappedKey(ciphertext) 字节摘要 */
    private byte[] wrappedKeyDigest;

    /** 收件证书策略摘要 */
    private byte[] recipientCertDigest;

    /** 原响应序列化中该 item 子消息 body 字节偏移 */
    private Integer itemWireOffset;

    /** 原响应序列化中该 item 子消息 body 字节长度 */
    private Integer itemWireLength;

    /** 设备导入结果 */
    private DeviceResult deviceResult;

    /** 非敏感导入证明摘要 */
    private String importProofDigest;

    /** 单用途确认时间 */
    private Instant confirmedAt;

    /** 设备导入结果 */
    public enum DeviceResult {
        PENDING, SUCCEEDED, FAILED, UNKNOWN
    }

    /**
     * 单用途 ACK 确认（真实验签后）。
     */
    public void confirmSucceeded(String importProofDigest, Instant at) {
        this.deviceResult = DeviceResult.SUCCEEDED;
        this.importProofDigest = importProofDigest;
        this.confirmedAt = at;
    }

    /**
     * 单用途失败（设备明确 FAILED）。
     */
    public void confirmFailed() {
        this.deviceResult = DeviceResult.FAILED;
        this.confirmedAt = Instant.now();
    }

    /**
     * 结果未知：禁止自动重放，转对账。
     */
    public void markUnknown() {
        this.deviceResult = DeviceResult.UNKNOWN;
    }
}
