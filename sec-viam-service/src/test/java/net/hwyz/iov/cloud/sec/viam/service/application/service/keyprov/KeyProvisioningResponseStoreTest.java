package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Keyprov 冻结证据存储单元测试（SEC-VIAM-DSN-CR-001 / G-2）
 * <p>
 * AES-GCM 加密/解密、密钥版本化轮换（旧版本可解密历史）、digest 校验 fail-closed、
 * KL1 persistKl1 建立 F/B/C。
 * </p>
 *
 * @author hwyz_leo
 */
class KeyProvisioningResponseStoreTest {

    private static final byte[] KEY_V1 = "abcdefghijklmnopqrstuvwxyz123456".getBytes(); // 32 字节
    private static final byte[] KEY_V2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ654321".getBytes(); // 32 字节

    private InMemoryBatchRepo repo;

    @BeforeEach
    void setUp() {
        repo = new InMemoryBatchRepo();
    }

    private void seedBatch(String requestId) {
        repo.save(ProvisioningBatch.builder()
                .requestId(requestId)
                .status(ProvisioningBatch.BatchState.PREPARING)
                .startedAt(Instant.now())
                .build());
    }

    private KeyProvisioningResponseStore store(String currentKeyBase64, int version, String versionedKeys) {
        return new KeyProvisioningResponseStore(repo, currentKeyBase64, version, versionedKeys);
    }

    private static byte[] sampleResponse() {
        net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse response =
                net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse.newBuilder()
                        .setRequestId("REQ-1")
                        .setResult(net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
                        .setExpireAtMs(60_000L)
                        .build();
        return KeyprovWireSerializer.serialize(response);
    }

    @Test
    void persistAndLoadRoundTrip() {
        KeyProvisioningResponseStore store = store(
                Base64.getEncoder().encodeToString(KEY_V1), 1, "");
        byte[] bytes = sampleResponse();
        seedBatch("REQ-1");
        store.persistKl1("REQ-1", bytes, Instant.ofEpochMilli(1_700_000_000_000L));
        ProvisioningBatch batch = repo.findByRequestId("REQ-1").orElseThrow();
        assertTrue(batch.getLifecycleProfile() != null);
        assertTrue(batch.getFirstIssuedAt() != null);
        assertTrue(batch.getAckDeadlineAt() != null);
        assertTrue(batch.getImmutableContentDigest() != null);
        byte[] loaded = store.load("REQ-1");
        assertArrayEquals(bytes, loaded);
    }

    @Test
    void keyRotationOldVersionStillDecrypts() {
        // v1 写入 → 轮换到 v2（保留 v1 历史密钥）→ 旧记录仍可解密
        String v1b64 = Base64.getEncoder().encodeToString(KEY_V1);
        String v2b64 = Base64.getEncoder().encodeToString(KEY_V2);
        KeyProvisioningResponseStore storeV1 = store(v1b64, 1, "");
        byte[] bytes = sampleResponse();
        seedBatch("REQ-2");
        storeV1.persist("REQ-2", bytes);
        KeyProvisioningResponseStore storeV2 = store(v2b64, 2, "1:" + v1b64);
        assertArrayEquals(bytes, storeV2.load("REQ-2"));
        // 新写入用 v2
        byte[] more = sampleResponse();
        seedBatch("REQ-3");
        storeV2.persistKl1("REQ-3", more, Instant.now());
        assertArrayEquals(more, storeV2.load("REQ-3"));
    }

    @Test
    void missingKeyVersionFailsClosed() {
        // 只有 v2 密钥，历史 v1 记录无法解密 → fail-closed 拒绝（不伪造重放）
        KeyProvisioningResponseStore storeV1 = store(
                Base64.getEncoder().encodeToString(KEY_V1), 1, "");
        seedBatch("REQ-4");
        storeV1.persist("REQ-4", sampleResponse());
        KeyProvisioningResponseStore storeV2Only = store(
                Base64.getEncoder().encodeToString(KEY_V2), 2, "");
        assertThrows(KeyprovEnvelopeException.class, () -> storeV2Only.load("REQ-4"));
    }

    @Test
    void tamperedPayloadRejected() {
        KeyProvisioningResponseStore store = store(
                Base64.getEncoder().encodeToString(KEY_V1), 1, "");
        seedBatch("REQ-5");
        store.persist("REQ-5", sampleResponse());
        // 篡改密文 → digest 校验失败
        ProvisioningBatch batch = repo.findByRequestId("REQ-5").orElseThrow();
        byte[] sealed = batch.getResponsePayload();
        sealed[sealed.length - 1] ^= 0x01;
        batch.setResponsePayload(sealed);
        assertThrows(KeyprovEnvelopeException.class, () -> store.load("REQ-5"));
    }

    static class InMemoryBatchRepo implements ProvisioningBatchRepository {
        final Map<String, ProvisioningBatch> byReq = new HashMap<>();
        long nextId = 1;

        @Override
        public Optional<ProvisioningBatch> findByRequestId(String requestId) {
            return Optional.ofNullable(byReq.get(requestId));
        }

        @Override
        public Optional<ProvisioningBatch> findByRequestIdForUpdate(String requestId) {
            return Optional.ofNullable(byReq.get(requestId));
        }

        @Override
        public void save(ProvisioningBatch batch) {
            if (batch.getId() == null) {
                batch.setId(nextId++);
            }
            ProvisioningBatch existing = byReq.get(batch.getRequestId());
            if (existing == null) {
                byReq.put(batch.getRequestId(), batch);
            } else {
                // 合并（内存替身保留对象引用，直接覆盖）
                byReq.put(batch.getRequestId(), batch);
            }
        }

        @Override
        public void saveItem(net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem item) {
        }

        @Override
        public List<net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem> listItemsByProvisioningId(Long provisioningId) {
            return List.of();
        }
    }
}
