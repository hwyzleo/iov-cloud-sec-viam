package net.hwyz.iov.cloud.sec.viam.service.common.util;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * 设备 CSR 前置校验（SEC-VIAM-DSN-CR-004 / D-VIAM-024）
 * <p>
 * 后台不得生成或替换设备 CSR：本类只校验「受信工位回读」的既有 CSR，并按既有错误码返回：
 * <ul>
 *   <li>702204：Base64/DER 非法、CSR 无法解析、自签名校验失败；</li>
 *   <li>702205：Subject CN 缺失、重复，或与目标主体规范化 hsmUid 不一致（含误用 deviceSn）；</li>
 *   <li>702206：CSR Subject 或 SAN 携带 VIN。</li>
 * </ul>
 * TBOX 与 IVI 使用同一套规则，禁止仅对 IVI 放松校验；私钥永不进入服务端。
 * </p>
 *
 * @author hwyz_leo
 */
public final class CertificateCsrValidator {

    /**
     * BC Provider：EC/EdDSA 等 SPKI OID → KeyFactory 映射需显式 Provider，否则验签会抛
     * {@code KeyFactory not available}。仅用于本类的 CSR 解析/自签名校验。
     */
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    private CertificateCsrValidator() {
    }

    /**
     * 校验通过的 CSR 事实（仅保留 DER 与公钥，不留 CSR 全文）。
     */
    public record ValidatedCsr(byte[] der, PublicKey publicKey) {

        /**
         * CSR DER 的 SHA-256 指纹（hex，小写），用于幂等摘要与审计。
         */
        public String fingerprint() {
            return ViamUtils.sha256Hex(der);
        }
    }

    /**
     * 完整校验：DER/自签名（702204）→ 唯一 CN=规范化 hsmUid（702205）→ 不含 VIN（702206）。
     *
     * @param csrDerBase64  CSR DER Base64（受信工位回读）
     * @param expectedHsmUid 目标 ACTIVE 安全主体的 hsmUid
     * @param vin           请求 VIN（非空时校验 CSR 不得携带）
     * @return 校验通过的 CSR 事实
     */
    public static ValidatedCsr validate(String csrDerBase64, String expectedHsmUid, String vin) {
        ValidatedCsr csr = parse(csrDerBase64);
        String expectedCn = ViamUtils.normalizeUid(expectedHsmUid);
        List<String> commonNames = extractCommonNames(csr.der());
        if (commonNames.size() != 1) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_SUBJECT_MISMATCH,
                    "CSR Subject CN 缺失或重复（数量=" + commonNames.size() + "）");
        }
        String actualCn = ViamUtils.normalizeUid(commonNames.get(0));
        if (expectedCn == null || !expectedCn.equals(actualCn)) {
            // CN=deviceSn、CN 为其他 UID、CN 缺失均归入同一确定性拒绝
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_SUBJECT_MISMATCH);
        }
        assertNoVin(csr.der(), vin);
        return csr;
    }

    /**
     * 解析并校验 CSR 自签名（不校验 CN/VIN）；失败均为 702204。
     */
    public static ValidatedCsr parse(String csrDerBase64) {
        byte[] der = decode(csrDerBase64);
        try {
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(der);
            boolean valid = request.isSignatureValid(
                    new JcaContentVerifierProviderBuilder()
                            .setProvider(BC_PROVIDER)
                            .build(request.getSubjectPublicKeyInfo()));
            if (!valid) {
                throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_INVALID, "CSR 自签名校验失败");
            }
            PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(request.getSubjectPublicKeyInfo());
            return new ValidatedCsr(der, publicKey);
        } catch (ViamServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_INVALID, "CSR 解析或自签名校验失败");
        }
    }

    /**
     * 计算 CSR 指纹（幂等摘要比对用）：可解码时用 DER 摘要，不可解码时退回原文摘要。
     * <p>
     * 非法 CSR 仍会在 {@link #validate} 阶段以 702204 拒绝；此方法不改变门禁。
     * </p>
     */
    public static String fingerprintOrRaw(String csrDerBase64) {
        if (csrDerBase64 == null || csrDerBase64.isBlank()) {
            return null;
        }
        try {
            return ViamUtils.sha256Hex(decode(csrDerBase64));
        } catch (ViamServiceException e) {
            return ViamUtils.sha256Hex(csrDerBase64.trim());
        }
    }

    /**
     * CSR Subject 中的全部 CN（保持顺序、不去重，用于识别「重复 CN」）。
     */
    static List<String> extractCommonNames(byte[] der) {
        try {
            X500Name subject = new PKCS10CertificationRequest(der).getSubject();
            List<String> values = new ArrayList<>();
            for (RDN rdn : subject.getRDNs(BCStyle.CN)) {
                values.add(rdn.getFirst().getValue().toString());
            }
            return values;
        } catch (Exception e) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_INVALID, "CSR Subject 解析失败");
        }
    }

    /**
     * CSR 不得携带 VIN（Subject 任一属性值或 SAN 均不得出现 VIN）。
     */
    static void assertNoVin(byte[] der, String vin) {
        String normalizedVin = vin == null ? null : vin.trim().toUpperCase(Locale.ROOT);
        if (normalizedVin == null || normalizedVin.isEmpty()) {
            return;
        }
        List<String> values = new ArrayList<>();
        try {
            X500Name subject = new PKCS10CertificationRequest(der).getSubject();
            for (RDN rdn : subject.getRDNs()) {
                for (var value : rdn.getTypesAndValues()) {
                    values.add(value.getValue().toString());
                }
            }
        } catch (Exception e) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_INVALID, "CSR Subject 解析失败");
        }
        values.addAll(extractSans(der));
        for (String value : values) {
            if (value != null && value.toUpperCase(Locale.ROOT).contains(normalizedVin)) {
                throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_CONTAINS_VIN);
            }
        }
    }

    /**
     * 尽力提取 SAN 文本（复用 FW-SEC 解析器；无 SAN 或解析失败按空集合处理）。
     */
    private static List<String> extractSans(byte[] der) {
        try {
            return net.hwyz.iov.cloud.framework.security.crypto.enrollment.CsrSanExtractor.extractSans(der);
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    /**
     * Base64（容错空白与 PEM 头尾）→ DER；空值或非法编码均为 702204。
     */
    static byte[] decode(String csrDerBase64) {
        if (csrDerBase64 == null || csrDerBase64.isBlank()) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_INVALID, "CSR 不能为空");
        }
        String normalized = csrDerBase64.replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            // 兼容直接粘贴 PEM：去掉头尾后重试一次
            String body = normalized
                    .replace("-----BEGINCERTIFICATEREQUEST-----", "")
                    .replace("-----ENDCERTIFICATEREQUEST-----", "");
            try {
                return Base64.getDecoder().decode(body);
            } catch (IllegalArgumentException ignored) {
                throw new ViamServiceException(ViamErrorCode.CERTIFICATE_CSR_INVALID,
                        "CSR 不是合法的 Base64/DER 编码");
            }
        }
    }
}
