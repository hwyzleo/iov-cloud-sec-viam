package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.MessageLite;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeDigestVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * PAR-PROTO V2C Keyprov Wire Mapper（迁入 VMD 既有实现，语义保持）。
 * <p>
 * 在最终 ciphertext/tag 与 deterministic parameters 确定后计算 9 字段 wireEnvelopeDigest，
 * 并组装 canonical {@link WrappedKeyItem}。使用官方生成类与既有 mapper/encoder，
 * 不手写 field 解析。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ParProtoWireMapperV1 {

    /** PAR-PROTO proto 枚举值 */
    private static final int ENVELOPE_FORMAT_ECDH_ES_P256_V1 = 1;
    private static final int SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM = 2;
    private static final int PURPOSE_UPLINK_AEAD = 1;
    private static final int PURPOSE_DOWNLINK_AEAD = 2;

    private final ObjectProvider<DerivedEnvelopeDigestVerifier> envelopeDigestVerifierProvider;

    public ParProtoWireMapperV1(ObjectProvider<DerivedEnvelopeDigestVerifier> envelopeDigestVerifierProvider) {
        this.envelopeDigestVerifierProvider = envelopeDigestVerifierProvider;
    }

    /**
     * 将派生封装结果映射为 canonical {@link WrappedKeyItem} 并计算 wire digest（固定流水线）。
     *
     * @throws KeyprovEnvelopeException view 为空、版本不支持、摘要不一致或字段不对应（不可重试）
     */
    public WireMappedItem map(DerivedWrappedKey source, KeyProvisioningWireContext ctx, DeviceBusinessKey directory) {
        Objects.requireNonNull(source, "DerivedWrappedKey must not be null");
        Objects.requireNonNull(ctx, "KeyProvisioningWireContext must not be null");
        DerivedWrappedKeyEnvelopeView view = source.envelope();
        if (view == null) {
            throw new KeyprovEnvelopeException(
                    "DerivedWrappedKey.envelope 为空（旧格式结果），禁止下发 envelope v1 且不得回退解析 envelopeBytes");
        }
        if (!(view instanceof EcdhEsP256EnvelopeViewV1 v1)) {
            throw new KeyprovEnvelopeException("不受支持的信封视图实现: " + view.getClass().getName());
        }
        if (!EcdhEsP256EnvelopeViewV1.ENVELOPE_FORMAT.equals(view.envelopeFormat())
                || view.formatVersion() != EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1) {
            throw new KeyprovEnvelopeException("不受支持的信封 format/version: "
                    + view.envelopeFormat() + "/v" + view.formatVersion());
        }

        if (source.wrappingSuite() != view.wrappingSuite()) {
            throw new KeyprovEnvelopeException("顶层 wrappingSuite 与 envelope 视图不一致");
        }
        if (!Arrays.equals(source.envelopeDigest(), view.envelopeDigest())) {
            throw new KeyprovEnvelopeException("顶层 envelopeDigest 与 envelope 视图不一致");
        }
        if (!Arrays.equals(source.kcv(), view.keyCheckValue())) {
            throw new KeyprovEnvelopeException("顶层 KCV 与 envelope 视图不一致");
        }
        if (source.operationId() != null && !source.operationId().equals(v1.operationId())) {
            throw new KeyprovEnvelopeException("顶层 operationId 与 envelope 视图不一致");
        }

        DerivedEnvelopeDigestVerifier verifier = envelopeDigestVerifierProvider.getIfAvailable();
        if (verifier == null) {
            throw new KeyprovEnvelopeException(
                    "DerivedEnvelopeDigestVerifier 未装配（crypto.provisioning.enabled=false）");
        }
        verifier.verify(view);

        EcdhEsP256EnvelopeParametersV1 parameters = EcdhEsP256EnvelopeParametersV1.newBuilder()
                .setFormatVersion(v1.formatVersion())
                .setServerEphemeralPublicKey(ByteString.copyFrom(v1.serverEphemeralPublicKey()))
                .setHkdfSalt(ByteString.copyFrom(v1.hkdfSalt()))
                .setHkdfContextVersion(v1.hkdfContextVersion())
                .setNonce(ByteString.copyFrom(v1.nonce()))
                .setAuthenticationTag(ByteString.copyFrom(v1.authenticationTag()))
                .setCanonicalAad(ByteString.copyFrom(v1.canonicalAad()))
                .setAadDigest(ByteString.copyFrom(v1.aadDigest()))
                .setRootKeyVersion(v1.rootKeyVersion())
                .setDerivationVersion(v1.derivationVersion())
                .setRecipientCertificateDigest(ByteString.copyFrom(v1.recipientCertificateDigest()))
                .setOperationId(v1.operationId())
                .build();
        byte[] parametersBytes = deterministicSerialize(parameters);
        assertViewWireParity(v1, parametersBytes);
        assertAadConsistency(v1);

        byte[] wireDigest = ParProtoWireCanonical.wireEnvelopeDigest(
                ENVELOPE_FORMAT_ECDH_ES_P256_V1,
                ctx.requestId(),
                ctx.businessDomain(),
                protoPurposeValue(v1.purpose()),
                v1.logicalKeyId(),
                v1.businessKeyVersion(),
                protoSuiteValue(v1.wrappingSuite()),
                v1.ciphertext(),
                parametersBytes);

        WrappedKeyItem.Builder builder = WrappedKeyItem.newBuilder()
                .setPurpose(KeyprovConstants.codeToProtoPurpose(KeyprovConstants.purposeCode(v1.purpose())))
                .setKeyId(v1.logicalKeyId())
                .setBusinessKeyVersion(v1.businessKeyVersion())
                .setKeyAlgorithm(canonicalKeyAlgorithm(directory))
                .setWrappingSuite(KeyprovConstants.frameworkSuiteToProto(v1.wrappingSuite()))
                .setWrappedKey(ByteString.copyFrom(v1.ciphertext()))
                .setParameters(ByteString.copyFrom(parametersBytes))
                .setEnvelopeDigest(ByteString.copyFrom(wireDigest))
                .setKeyCheckValue(ByteString.copyFrom(v1.keyCheckValue()))
                .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
        if (directory != null) {
            if (directory.getValidFrom() == null || directory.getValidTo() == null) {
                throw new KeyprovEnvelopeException(
                        "目录行缺少有效期（validFrom/validTo 缺失），拒绝下发 envelope: keyId="
                                + directory.getKeyId());
            }
            builder.setValidFromMs(toEpochMs(directory.getValidFrom()));
            builder.setValidToMs(toEpochMs(directory.getValidTo()));
        }
        return new WireMappedItem(
                builder.build(),
                wireDigest,
                v1.coreEnvelopeDigest(),
                ParProtoWireCanonical.sha256(parametersBytes),
                ParProtoWireCanonical.sha256(v1.ciphertext()),
                v1.aadProfileId() != null ? v1.aadProfileId() : ParProtoWireCanonical.AAD_PROFILE);
    }

    private static int protoPurposeValue(KeyPurpose purpose) {
        if (purpose == KeyPurpose.UPLINK_AEAD) {
            return PURPOSE_UPLINK_AEAD;
        }
        if (purpose == KeyPurpose.DOWNLINK_AEAD) {
            return PURPOSE_DOWNLINK_AEAD;
        }
        throw new KeyprovEnvelopeException("PAR-PROTO wire digest: 不受支持的 purpose=" + purpose);
    }

    private static int protoSuiteValue(WrappingSuite suite) {
        if (suite == WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM) {
            return SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM;
        }
        throw new KeyprovEnvelopeException("PAR-PROTO wire digest: 不受支持的 wrappingSuite=" + suite);
    }

    private static byte[] deterministicSerialize(MessageLite message) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(message.getSerializedSize());
            CodedOutputStream output = CodedOutputStream.newInstance(buffer);
            output.useDeterministicSerialization();
            message.writeTo(output);
            output.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new KeyprovEnvelopeException("parameters deterministic serialization 失败", e);
        }
    }

    private static void assertViewWireParity(EcdhEsP256EnvelopeViewV1 view, byte[] parametersBytes) {
        EcdhEsP256EnvelopeParametersV1 parsed;
        try {
            parsed = EcdhEsP256EnvelopeParametersV1.parseFrom(parametersBytes);
        } catch (IOException e) {
            throw new KeyprovEnvelopeException("parameters 反序列化失败", e);
        }
        boolean consistent = parsed.getFormatVersion() == view.formatVersion()
                && Arrays.equals(parsed.getServerEphemeralPublicKey().toByteArray(), view.serverEphemeralPublicKey())
                && Arrays.equals(parsed.getHkdfSalt().toByteArray(), view.hkdfSalt())
                && parsed.getHkdfContextVersion().equals(view.hkdfContextVersion())
                && Arrays.equals(parsed.getNonce().toByteArray(), view.nonce())
                && Arrays.equals(parsed.getAuthenticationTag().toByteArray(), view.authenticationTag())
                && Arrays.equals(parsed.getCanonicalAad().toByteArray(), view.canonicalAad())
                && Arrays.equals(parsed.getAadDigest().toByteArray(), view.aadDigest())
                && parsed.getRootKeyVersion() == view.rootKeyVersion()
                && parsed.getDerivationVersion().equals(view.derivationVersion())
                && Arrays.equals(parsed.getRecipientCertificateDigest().toByteArray(),
                        view.recipientCertificateDigest())
                && parsed.getOperationId().equals(view.operationId());
        if (!consistent) {
            throw new KeyprovEnvelopeException("view→wire 字段不一一对应，拒绝返回部分 wire material");
        }
    }

    private static void assertAadConsistency(EcdhEsP256EnvelopeViewV1 view) {
        if (view.canonicalAad() == null || view.canonicalAad().length == 0) {
            throw new KeyprovEnvelopeException("view.canonicalAad 为空，拒绝计算 wire digest");
        }
        if (view.aadDigest() == null || view.aadDigest().length != 32) {
            throw new KeyprovEnvelopeException("view.aadDigest 缺失或长度非法，拒绝计算 wire digest");
        }
        byte[] recomputed = ParProtoWireCanonical.aadDigest(view.canonicalAad());
        if (!Arrays.equals(recomputed, view.aadDigest())) {
            throw new KeyprovEnvelopeException("aad_digest != SHA-256(canonical_aad)，拒绝计算 wire digest");
        }
    }

    private static long toEpochMs(Instant time) {
        return time.toEpochMilli();
    }

    private static String canonicalKeyAlgorithm(DeviceBusinessKey directory) {
        if (directory == null || directory.getAlgorithm() == null
                || directory.getAlgorithm().isBlank()) {
            return "";
        }
        String algorithm = directory.getAlgorithm();
        if ("AES".equals(algorithm)) {
            return KeyprovConstants.KEY_ALGORITHM_ECDH_ES_V1;
        }
        return algorithm;
    }

    /** 确定性自检（readiness / 测试）。 */
    public static boolean deterministicSelfCheck() {
        byte[] a = ParProtoWireCanonical.wireEnvelopeDigest(
                ENVELOPE_FORMAT_ECDH_ES_P256_V1, "probe-request", "V2C_COMM",
                PURPOSE_UPLINK_AEAD, "logical-probe", 7L, SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{1, 2, 3}, new byte[]{4, 5, 6, 7});
        byte[] b = ParProtoWireCanonical.wireEnvelopeDigest(
                ENVELOPE_FORMAT_ECDH_ES_P256_V1, "probe-request", "V2C_COMM",
                PURPOSE_UPLINK_AEAD, "logical-probe", 7L, SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{1, 2, 3}, new byte[]{4, 5, 6, 7});
        return a != null && a.length == 32 && Arrays.equals(a, b);
    }

    /** 映射结果。 */
    public record WireMappedItem(WrappedKeyItem item, byte[] wireEnvelopeDigest, byte[] coreEnvelopeDigest,
                                 byte[] parametersDigest, byte[] wrappedKeyDigest, String aadProfileId) {
    }
}
