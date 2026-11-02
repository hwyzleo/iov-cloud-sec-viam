package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keyprov 最终 Response 字节级幂等重放存储（迁入 VMD 既有实现，密钥版本化）。
 * <p>
 * 在批次表（tb_viam_business_key_provisioning，幂等键=requestId）受控保存最终
 * KeyProvisioningResponse 事实：
 * <ul>
 *   <li>response_payload：AES-GCM 加密 BLOB（nonce(12) ‖ ciphertext+tag(16)）；</li>
 *   <li>response_digest：SHA-256(final response bytes) hex，重放完整性校验；</li>
 *   <li>response_codec_version：{@code PAR_PROTO_KEYPROV_AAD_V1#kv&lt;N&gt;}（含密钥版本，支持轮换解密历史）；</li>
 *   <li>response_persisted_at：首次持久化时间（重放不更新）。</li>
 * </ul>
 * 约束：
 * <ul>
 *   <li>密钥经 Secret 注入（{@code viam.keyprov.response-store.key}，Base64 AES-256），
 *       不随启动随机生成；轮换时以 {@code viam.keyprov.response-store.keys.&lt;version&gt;} 登记多版本，
 *       旧版本保留可解密历史记录；</li>
 *   <li>nonce 每次随机生成（SecureRandom 12 字节），不复用；</li>
 *   <li>Response 必须在首次发送前持久化；同 requestId 重放直接返回原 bytes，
 *       不重新 derive/serialize/map；</li>
 *   <li>KL1 首次完整双用途响应原子持久化并建立 F/B 与不可变内容摘要（persistKl1）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class KeyProvisioningResponseStore {

    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_LENGTH = 12;
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final String CODEC_PREFIX = ParProtoWireCanonical.AAD_PROFILE;

    private final ProvisioningBatchRepository provisioningRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    /** 当前密钥版本（默认 1） */
    private final int currentKeyVersion;

    /** 多版本密钥环（version → AES key bytes）；历史版本用于解密旧记录 */
    private final Map<Integer, byte[]> keyRing = new LinkedHashMap<>();

    public KeyProvisioningResponseStore(
            ProvisioningBatchRepository provisioningRepository,
            @Value("${viam.keyprov.response-store.key:}") String currentKeyBase64,
            @Value("${viam.keyprov.response-store.key-version:1}") int keyVersion,
            @Value("${viam.keyprov.response-store.keys:}") String versionedKeysBase64) {
        this.provisioningRepository = provisioningRepository;
        this.currentKeyVersion = keyVersion;
        registerKey(keyVersion, currentKeyBase64, "current");
        if (versionedKeysBase64 != null && !versionedKeysBase64.isBlank()) {
            // 格式：version:base64,version:base64（逗号分隔；轮换时登记旧版本）
            for (String entry : versionedKeysBase64.split(",")) {
                String[] parts = entry.split(":", 2);
                if (parts.length == 2) {
                    registerKey(Integer.parseInt(parts[0].trim()), parts[1].trim(), "versioned");
                }
            }
        }
    }

    private void registerKey(int version, String base64, String label) {
        if (base64 == null || base64.isBlank()) {
            if ("current".equals(label)) {
                log.warn("Keyprov Response 存储当前密钥未配置（viam.keyprov.response-store.key），重放/持久化将 fail-closed");
            }
            return;
        }
        try {
            byte[] key = Base64.getDecoder().decode(base64.trim());
            if (key.length != 16 && key.length != 24 && key.length != 32) {
                throw new IllegalArgumentException("密钥长度非法（需 16/24/32 字节）");
            }
            keyRing.put(version, key);
        } catch (IllegalArgumentException e) {
            log.error("Keyprov Response 存储密钥非法（{}）: {}", label, e.getMessage());
        }
    }

    /**
     * 是否就绪：当前密钥已注入。
     */
    public boolean productionReady() {
        return keyRing.containsKey(currentKeyVersion);
    }

    /**
     * 首次发送前持久化最终 Response 字节（幂等键=requestId）。
     */
    public void persist(String requestId, byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) {
            throw new KeyprovEnvelopeException("Response 字节为空，拒绝持久化");
        }
        ProvisioningBatch batch = requireBatch(requestId);
        batch.setResponsePayload(encrypt(responseBytes, currentKeyVersion));
        batch.setResponseDigest(hex(Kl1WireCodec.sha256(responseBytes)));
        batch.setResponseCodecVersion(codecVersion(currentKeyVersion));
        batch.setResponsePersistedAt(Instant.now());
        provisioningRepository.save(batch);
    }

    /**
     * KL1：首次完整双用途响应原子持久化并建立 F/B 与不可变内容摘要。
     * <p>
     * F=首次持久化时间（不可滑动），B=F+300s；immutable_content_digest 从已验证原始 bytes 计算
     * （去掉唯一外层 field4 的 C）。重跑迁移/续签均不重置 F/B。
     * </p>
     */
    public void persistKl1(String requestId, byte[] responseBytes, Instant now) {
        if (responseBytes == null || responseBytes.length == 0) {
            throw new KeyprovEnvelopeException("KL1 Response 字节为空，拒绝持久化");
        }
        ProvisioningBatch batch = requireBatch(requestId);
        byte[] digest = Kl1WireCodec.immutableContentDigest(responseBytes);
        batch.setResponsePayload(encrypt(responseBytes, currentKeyVersion));
        batch.setResponseDigest(hex(Kl1WireCodec.sha256(responseBytes)));
        batch.setResponseCodecVersion(codecVersion(currentKeyVersion));
        batch.setResponsePersistedAt(now);
        batch.setLifecycleProfile(Kl1Constants.PROFILE);
        batch.setFirstIssuedAt(now);
        batch.setAckDeadlineAt(now.plus(Kl1Constants.BATCH_MS, ChronoUnit.MILLIS));
        batch.setImmutableContentDigest(hex(digest));
        provisioningRepository.save(batch);
    }

    /**
     * 受保护 payload 加密（租约表复用同一密钥策略）。
     */
    public byte[] seal(byte[] plain) {
        return encrypt(plain, currentKeyVersion);
    }

    /**
     * 受保护 payload 解密。
     */
    public byte[] open(byte[] sealed, String codecVersion) {
        return decrypt(sealed, codecVersion);
    }

    /**
     * 按 requestId 读取原 Response 字节（重放）。返回 {@code null} 表示批次不存在或尚无持久化响应。
     *
     * @throws KeyprovEnvelopeException 解密失败或 digest 校验不一致（fail-closed，禁止伪造重放）
     */
    public byte[] load(String requestId) {
        ProvisioningBatch batch = provisioningRepository.findByRequestId(requestId).orElse(null);
        if (batch == null || batch.getResponsePayload() == null) {
            return null;
        }
        byte[] plain = decrypt(batch.getResponsePayload(), batch.getResponseCodecVersion());
        if (batch.getResponseDigest() != null
                && !batch.getResponseDigest().equalsIgnoreCase(hex(Kl1WireCodec.sha256(plain)))) {
            throw new KeyprovEnvelopeException("Response 重放字节完整性校验失败，拒绝返回");
        }
        return plain;
    }

    private ProvisioningBatch requireBatch(String requestId) {
        return provisioningRepository.findByRequestId(requestId)
                .orElseThrow(() -> new KeyprovEnvelopeException("Response 持久化失败：批次不存在 requestId=" + requestId));
    }

    private static String codecVersion(int version) {
        return CODEC_PREFIX + "#kv" + version;
    }

    private byte[] encrypt(byte[] plain, int version) {
        if (!keyRing.containsKey(version)) {
            throw new KeyprovEnvelopeException("Keyprov Response 存储密钥未配置（version=" + version + "），禁止持久化");
        }
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            secureRandom.nextBytes(nonce); // 每次随机，nonce 不复用
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec(version), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plain);
            byte[] sealed = new byte[NONCE_LENGTH + ciphertext.length];
            System.arraycopy(nonce, 0, sealed, 0, NONCE_LENGTH);
            System.arraycopy(ciphertext, 0, sealed, NONCE_LENGTH, ciphertext.length);
            return sealed;
        } catch (KeyprovEnvelopeException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyprovEnvelopeException("Response 加密失败（fail-closed）", e);
        }
    }

    private byte[] decrypt(byte[] sealed, String codecVersion) {
        int version = resolveVersion(codecVersion);
        if (!keyRing.containsKey(version)) {
            throw new KeyprovEnvelopeException("Keyprov Response 存储密钥版本不可用（version=" + version
                    + "），禁止重放/解密历史记录");
        }
        try {
            if (sealed == null || sealed.length < NONCE_LENGTH + GCM_TAG_BITS / 8) {
                throw new KeyprovEnvelopeException("Response 密文长度非法");
            }
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(sealed, 0, nonce, 0, NONCE_LENGTH);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec(version), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(sealed, NONCE_LENGTH, sealed.length - NONCE_LENGTH);
        } catch (KeyprovEnvelopeException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyprovEnvelopeException("Response 解密失败（fail-closed，不得回退重放）", e);
        }
    }

    private int resolveVersion(String codecVersion) {
        if (codecVersion == null || !codecVersion.contains("#kv")) {
            // 历史/未版本化记录：回退当前密钥（仅当无版本标记时；V1 基线为空库，无存量）
            return currentKeyVersion;
        }
        try {
            return Integer.parseInt(codecVersion.substring(codecVersion.indexOf("#kv") + 3));
        } catch (NumberFormatException e) {
            throw new KeyprovEnvelopeException("Response codec_version 密钥版本非法: " + codecVersion);
        }
    }

    private SecretKeySpec keySpec(int version) {
        return new SecretKeySpec(keyRing.get(version), "AES");
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
