package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * KL1 交付租约实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 * <p>
 * 内容幂等 + 外层租约签发：批次+租约序号唯一；messageId 唯一（同一 messageId 不得对应
 * 不同 bytes）；E=min(now+60s, B-30s)；E-now<20s 不签发。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyProvisioningLease {

    /** 主键（DB 自增；插入后回填） */
    private Long id;

    /** 批次外键 */
    private Long provisioningId;

    /** 本批次租约序号（从 1 递增，原子签发） */
    private int leaseSeq;

    /** 租约签发时间（服务端 UTC） */
    private Instant issuedAt;

    /** KL1 E=min(now+60s, B-30s)；E-now<20s 不签发 */
    private Instant expireAt;

    /** 本次应用投递新 messageId（唯一；同 messageId 不得对应不同 bytes） */
    private String messageId;

    /** 应用投递 correlationId（→Request） */
    private String correlationId;

    /** 本次完整响应 bytes 的 SHA-256（含本次 E） */
    private String deliveryPayloadDigest;

    /** 不可变内容摘要（=批次 immutable_content_digest） */
    private String contentDigest;

    /** 受保护原传输 bytes（AES-GCM 加密 BLOB；与 payloadRef 二选一） */
    private byte[] payload;

    /** 不可变受控对象引用 */
    private String payloadRef;

    /**
     * 租约是否已过期。
     */
    public boolean isExpired(Instant now) {
        return expireAt != null && !expireAt.isAfter(now);
    }
}
