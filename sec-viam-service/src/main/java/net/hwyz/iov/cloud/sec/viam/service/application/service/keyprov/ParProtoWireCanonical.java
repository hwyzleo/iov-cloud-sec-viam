package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * PAR-PROTO V2C Keyprov wire canonical 编码 helper（迁入 VMD 既有实现，语义保持）。
 * <p>
 * 仅实现 PAR-PROTO 权威 registry：AAD profile（10 段）与 wire digest（9 段）的 segment 编码。
 * 本 helper 不依赖业务密钥、不解析 FW 私有 envelopeBytes、不手写 Protobuf 字段编码。
 * </p>
 *
 * @author hwyz_leo
 */
public final class ParProtoWireCanonical {

    private ParProtoWireCanonical() {
    }

    /** PAR-PROTO wire digest profile */
    public static final String WIRE_PROFILE = "PAR_PROTO_KEYPROV_ECDH_ES_P256_V1";

    /** PAR-PROTO AAD profile */
    public static final String AAD_PROFILE = "PAR_PROTO_KEYPROV_AAD_V1";

    /** canonical AAD 最大长度（proto 契约 canonical_aad <= 1 KiB） */
    static final int MAX_CANONICAL_AAD_BYTES = 1024;

    /** 段编码：uint32be(len) || bytes */
    public static byte[] segment(byte[] value) {
        if (value == null) {
            value = new byte[0];
        }
        if (value.length > 0xFFFF_FFFFL) {
            throw new IllegalStateException("PAR-PROTO segment 超长: " + value.length);
        }
        byte[] out = new byte[4 + value.length];
        writeUint32Be(out, 0, value.length);
        System.arraycopy(value, 0, out, 4, value.length);
        return out;
    }

    /** UTF-8 字符串段 */
    public static byte[] segmentUtf8(String value) {
        return segment(value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8));
    }

    /** unsigned varint（protobuf LEB128）段；仅接受非负 int 枚举值 */
    public static byte[] segmentVarint(int value) {
        if (value < 0) {
            throw new IllegalStateException("PAR-PROTO unsigned varint 不接受负值: " + value);
        }
        return segment(unsignedVarint(value));
    }

    /** uint64be（8 字节大端）段 */
    public static byte[] segmentUint64(long value) {
        byte[] bigEndian = new byte[8];
        for (int i = 0; i < 8; i++) {
            bigEndian[7 - i] = (byte) (value >>> (i * 8));
        }
        return segment(bigEndian);
    }

    /** unsigned varint 原始字节（protobuf LEB128，小端组序） */
    public static byte[] unsignedVarint(int value) {
        long remaining = Integer.toUnsignedLong(value);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(5);
        while (true) {
            if ((remaining & ~0x7FL) == 0) {
                out.write((int) remaining);
                break;
            }
            out.write((int) ((remaining & 0x7F) | 0x80));
            remaining >>>= 7;
        }
        return out.toByteArray();
    }

    /**
     * 计算 PAR-PROTO 9 段 wireEnvelopeDigest。
     */
    public static byte[] wireEnvelopeDigest(int envelopeFormatValue, String requestId, String businessDomain,
                                            int purposeValue, String keyId, long businessKeyVersion,
                                            int wrappingSuiteValue, byte[] wrappedKey, byte[] parametersBytes) {
        byte[] input = wireDigestInput(envelopeFormatValue, requestId, businessDomain,
                purposeValue, keyId, businessKeyVersion, wrappingSuiteValue, wrappedKey, parametersBytes);
        return sha256(input);
    }

    /**
     * 组装 9 段 wire digest input（共且仅有 9 个顶层 segment；顺序固定，禁止重排）。
     */
    public static byte[] wireDigestInput(int envelopeFormatValue, String requestId, String businessDomain,
                                         int purposeValue, String keyId, long businessKeyVersion,
                                         int wrappingSuiteValue, byte[] wrappedKey, byte[] parametersBytes) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(256);
        out.writeBytes(segmentVarint(envelopeFormatValue));
        out.writeBytes(segmentUtf8(requestId));
        out.writeBytes(segmentUtf8(businessDomain));
        out.writeBytes(segmentVarint(purposeValue));
        out.writeBytes(segmentUtf8(keyId));
        out.writeBytes(segmentUint64(businessKeyVersion));
        out.writeBytes(segmentVarint(wrappingSuiteValue));
        out.writeBytes(segment(wrappedKey == null ? new byte[0] : wrappedKey));
        out.writeBytes(segment(parametersBytes == null ? new byte[0] : parametersBytes));
        return out.toByteArray();
    }

    /**
     * 组装 PAR-PROTO AAD profile（10 段；顺序固定，禁止重排；长度上限 1 KiB）。
     */
    public static byte[] canonicalAad(int envelopeFormatValue, int wrappingSuiteValue, int purposeValue,
                                      long businessKeyVersion, long rootKeyVersion, byte[] recipientCertificateDigest,
                                      String requestId, String businessDomain, String keyId, String derivationVersion) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(128);
        out.writeBytes(segmentVarint(envelopeFormatValue));
        out.writeBytes(segmentVarint(wrappingSuiteValue));
        out.writeBytes(segmentVarint(purposeValue));
        out.writeBytes(segmentUint64(businessKeyVersion));
        out.writeBytes(segmentUint64(rootKeyVersion));
        out.writeBytes(segment(recipientCertificateDigest == null ? new byte[0] : recipientCertificateDigest));
        out.writeBytes(segmentUtf8(requestId));
        out.writeBytes(segmentUtf8(businessDomain));
        out.writeBytes(segmentUtf8(keyId));
        out.writeBytes(segmentUtf8(derivationVersion));
        byte[] aad = out.toByteArray();
        if (aad.length > MAX_CANONICAL_AAD_BYTES) {
            throw new IllegalStateException("PAR-PROTO canonical AAD 超过 1 KiB: " + aad.length);
        }
        return aad;
    }

    /** aadDigest = SHA-256(canonicalAad) */
    public static byte[] aadDigest(byte[] canonicalAad) {
        return sha256(canonicalAad);
    }

    private static void writeUint32Be(byte[] target, int offset, int value) {
        target[offset] = (byte) (value >>> 24);
        target[offset + 1] = (byte) (value >>> 16);
        target[offset + 2] = (byte) (value >>> 8);
        target[offset + 3] = (byte) value;
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
