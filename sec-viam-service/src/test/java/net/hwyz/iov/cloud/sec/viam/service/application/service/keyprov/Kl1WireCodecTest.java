package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KL1 wire codec 单元测试（SEC-VIAM-DSN-CR-001 / G-2）
 * <p>
 * field4=expire_at_ms 唯一外层 varint 的定位/移除/patch；immutable_content_digest 与
 * delivery_payload_digest 语义；多重 field4/错误 wire type/缺失 field4 拒绝。
 * </p>
 *
 * @author hwyz_leo
 */
class Kl1WireCodecTest {

    private byte[] responseWire(long expireAtMs) {
        KeyProvisioningResponse response = KeyProvisioningResponse.newBuilder()
                .setRequestId("REQ-001")
                .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
                .setExpireAtMs(expireAtMs)
                .build();
        return KeyprovWireSerializer.serialize(response);
    }

    @Test
    void patchField4OnlyChangesExpireAt() {
        byte[] original = responseWire(60_000L);
        byte[] patched = Kl1WireCodec.patchField4(original, 45_000L);
        KeyProvisioningResponse parsed;
        try {
            parsed = KeyProvisioningResponse.parseFrom(patched);
        } catch (Exception e) {
            throw new AssertionError("patch 后不可解析", e);
        }
        assertEquals(45_000L, parsed.getExpireAtMs());
        // 内容字节 C 不变 → immutable_content_digest 一致（续签后必须相等）
        assertArrayEquals(Kl1WireCodec.immutableContentDigest(original),
                Kl1WireCodec.immutableContentDigest(patched));
        // delivery digest 不同（含本次 E）
        assertNotEquals(Kl1WireCodec.deliveryPayloadDigest(original),
                Kl1WireCodec.deliveryPayloadDigest(patched));
    }

    @Test
    void missingField4Rejected() {
        byte[] wire = KeyprovWireSerializer.serialize(KeyProvisioningResponse.newBuilder()
                .setRequestId("REQ-001")
                .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
                .build());
        assertThrows(IllegalArgumentException.class, () -> Kl1WireCodec.patchField4(wire, 1L));
        assertThrows(IllegalArgumentException.class, () -> Kl1WireCodec.locateField4(wire));
    }

    @Test
    void negativeExpireRejected() {
        byte[] wire = responseWire(60_000L);
        assertThrows(IllegalArgumentException.class, () -> Kl1WireCodec.patchField4(wire, -1L));
    }

    @Test
    void malformedWireRejected() {
        assertThrows(IllegalArgumentException.class, () -> Kl1WireCodec.locateField4(new byte[0]));
        // 非 field4 的畸形 length-delimited
        byte[] bad = new byte[]{0x1A, (byte) 0x80, 0x7F, 0x01}; // field3 len=~16384 超界
        assertThrows(IllegalArgumentException.class, () -> Kl1WireCodec.locateField4(bad));
    }

    @Test
    void contentDigestDomainFixed() {
        byte[] wire = responseWire(60_000L);
        byte[] digest = Kl1WireCodec.immutableContentDigest(wire);
        assertEquals(32, digest.length);
        // 确定性
        assertArrayEquals(digest, Kl1WireCodec.immutableContentDigest(wire));
    }

    @Test
    void varintRoundTrip() {
        assertArrayEquals(new byte[]{(byte) 0x20}, Kl1WireCodec.varint(4L << 3));
        assertArrayEquals(new byte[]{(byte) 0xAC, 0x02}, Kl1WireCodec.varint(300L));
    }

    @Test
    void deterministicSelfCheck() {
        assertTrue(ParProtoWireMapperV1.deterministicSelfCheck());
    }
}
