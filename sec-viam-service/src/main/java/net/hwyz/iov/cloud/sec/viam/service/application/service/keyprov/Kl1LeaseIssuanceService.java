package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.KeyProvisioningLease;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.KeyProvisioningLeaseRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.ProtocolError;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * KL1 交付租约签发服务（迁入 VMD 既有实现）。
 * <p>
 * WAIT_DEVICE_ACK 批次按 KL1 规范签发新租约：
 * <ul>
 *   <li>E = min(now + 60s, B - 30s)；E - now &lt; 20s → EXPIRED 响应（无 items，不 SUCCEEDED）；</li>
 *   <li>取已冻结原 Response raw bytes，仅对外层 field4 做受限 wire patch（禁止
 *       domain-map → protobuf 重建 items）；新 payload 摘要单独计算（delivery_payload_digest），
 *       不覆盖原 response_digest；</li>
 *   <li>原子落租约（批次+租约序号唯一、messageId 唯一、受保护 payload）并更新批次 lease_seq；</li>
 *   <li>同 requestId 重放绝不调用 Provider/重 wrap；</li>
 *   <li>同 messageId 传输重放保持原字节（不再次续租）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class Kl1LeaseIssuanceService {

    private final KeyProvisioningResponseStore responseStore;
    private final KeyProvisioningLeaseRepository leaseRepository;
    private final ProvisioningBatchRepository provisioningRepository;

    /**
     * 签发结果。
     */
    public static final class LeaseIssueResult {
        private final KeyProvisioningResponse response;
        private final byte[] deliveryBytes;
        private final long expireAtMs;
        private final String messageId;

        private LeaseIssueResult(KeyProvisioningResponse response, byte[] deliveryBytes, long expireAtMs, String messageId) {
            this.response = response;
            this.deliveryBytes = deliveryBytes;
            this.expireAtMs = expireAtMs;
            this.messageId = messageId;
        }

        public KeyProvisioningResponse response() {
            return response;
        }

        public byte[] deliveryBytes() {
            return deliveryBytes;
        }

        public long expireAtMs() {
            return expireAtMs;
        }

        public String messageId() {
            return messageId;
        }

        public boolean expiredNoItems() {
            return deliveryBytes == null;
        }
    }

    /**
     * 为 WAIT_DEVICE_ACK 批次签发新租约（调用方须已在事务内）。
     *
     * @param batch       KL1 批次（WAIT_DEVICE_ACK，建议持有行锁）
     * @param now         服务端 UTC 当前时间
     * @param safetyValid KL1 readiness/证书/材料安全期限检查通过
     * @throws KeyprovEnvelopeException 原响应缺失/损坏（fail-closed，STORE_QUARANTINE）
     */
    @Transactional(rollbackFor = Exception.class)
    public LeaseIssueResult issue(ProvisioningBatch batch, Instant now, boolean safetyValid) {
        if (batch == null || !Kl1Constants.PROFILE.equals(batch.getLifecycleProfile())
                || batch.getStatus() != ProvisioningBatch.BatchState.WAIT_DEVICE_ACK) {
            throw new KeyprovEnvelopeException("KL1 租约签发前提不满足: requestId="
                    + (batch == null ? "null" : batch.getRequestId()) + ", state="
                    + (batch == null ? "null" : batch.getStatus()));
        }
        long nowMs = now.toEpochMilli();
        Kl1LifecycleDecide.IssueDecision decision = Kl1LifecycleDecide.issue(
                nowMs, batch.getAckDeadlineAt().toEpochMilli(), safetyValid);
        if ("EXPIRED_NO_ITEMS".equals(decision.action())) {
            return new LeaseIssueResult(expiredResponse(batch.getRequestId()), null, 0L, null);
        }
        if ("SECURITY_BLOCKED".equals(decision.action())) {
            throw new KeyprovEnvelopeException(
                    "KL1 安全期限不覆盖拟签发 E，停止交付: requestId=" + batch.getRequestId());
        }
        byte[] original = responseStore.load(batch.getRequestId());
        if (original == null) {
            throw new KeyprovEnvelopeException(
                    "KL1 原响应缺失，STORE_QUARANTINE（禁止重新 derive 补齐）: requestId=" + batch.getRequestId());
        }
        byte[] patched = Kl1WireCodec.patchField4(original, decision.expireAtMs());
        KeyProvisioningResponse parsed;
        try {
            parsed = KeyProvisioningResponse.parseFrom(patched);
        } catch (Exception e) {
            throw new KeyprovEnvelopeException("KL1 patch 后响应损坏（fail-closed）: requestId=" + batch.getRequestId(), e);
        }
        final String messageId = newMessageId();
        int seq = (batch.getLeaseSeq() == null ? 0 : batch.getLeaseSeq()) + 1;
        KeyProvisioningLease lease = KeyProvisioningLease.builder()
                .provisioningId(batch.getId())
                .leaseSeq(seq)
                .issuedAt(now)
                .expireAt(Instant.ofEpochMilli(decision.expireAtMs()))
                .messageId(messageId)
                .correlationId(batch.getRequestId())
                .deliveryPayloadDigest(hex(Kl1WireCodec.deliveryPayloadDigest(patched)))
                .contentDigest(batch.getImmutableContentDigest())
                .payload(responseStore.seal(patched))
                .build();
        leaseRepository.save(lease);
        batch.setLeaseSeq(seq);
        provisioningRepository.save(batch);
        log.info("KL1 租约签发: requestId={}, leaseSeq={}, messageId={}, E={}",
                batch.getRequestId(), seq, messageId, decision.expireAtMs());
        return new LeaseIssueResult(parsed, patched, decision.expireAtMs(), messageId);
    }

    /**
     * 同 messageId 传输重放：返回该次交付原字节（不再次续租、不调用 Provider）。
     *
     * @throws KeyprovEnvelopeException 租约不存在/受保护 payload 损坏（fail-closed）
     */
    public byte[] replayByMessageId(String messageId) {
        KeyProvisioningLease lease = leaseRepository.findByMessageId(messageId)
                .orElseThrow(() -> new KeyprovEnvelopeException("messageId 无对应租约，拒绝传输重放: " + messageId));
        return responseStore.open(lease.getPayload(), null);
    }

    private KeyProvisioningResponse expiredResponse(String requestId) {
        return KeyProvisioningResponse.newBuilder()
                .setRequestId(requestId == null ? "" : requestId)
                .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_EXPIRED)
                .setError(ProtocolError.newBuilder()
                        .setCode(KeyprovConstants.ERR_EXPIRED)
                        .setRetryable(false)
                        .setAction("DO_NOT_RETRY")
                        .setMessage("bundle到期无items可交付，请以原requestId查询Status")
                        .build())
                .build();
    }

    private static String newMessageId() {
        return "kl1-" + UUID.randomUUID().toString().replace("-", "");
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** 便捷：校验批次为 KL1 WAIT_DEVICE_ACK（供 status/replay 分支）。 */
    public static boolean isKl1WaitingAck(ProvisioningBatch batch) {
        return batch != null && Kl1Constants.PROFILE.equals(batch.getLifecycleProfile())
                && batch.getStatus() == ProvisioningBatch.BatchState.WAIT_DEVICE_ACK;
    }
}
