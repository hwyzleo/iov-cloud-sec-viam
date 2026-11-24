package net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofType;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofInvalidException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofEvidence;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofVerifier;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * 设备证明校验适配器（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-3 / D-VIAM-3-02）
 * <p>
 * 复用既有 framework-security PKI 能力（证书状态 + 证书注册门面 + VIAM 证书登记事实），
 * 不新建第二套 PKI 客户端、不做任何写操作。
 * <p>
 * 已登记证书材料一律经 {@link CertEnrollmentAdapter#getCertificate(String)} 按 PKI 申请编号取用：
 * 当前部署为 step-ca，其不提供「按序列号回查已签发证书」的 CA 路由
 * （FW-SEC-DSN-CR-008 §5.3），故禁止再用 {@code PkiClient#queryCertificate(serial)}。
 * </p>
 * <ul>
 *   <li>MTLS_CERT：解析叶子证书 → 序列号/指纹与登记事实比对 → 链/有效期/吊销（OCSP 优先）→ Subject CN 作为设备身份。</li>
 *   <li>KEY_SIGNATURE：以 deviceId 定位已登记 ACTIVE 证书 → 经 PKI 重取叶子证书 → 用其公钥校验
 *       对 nonce 原文（UTF-8）的签名 → 同一套状态校验。</li>
 * </ul>
 * 任何无法获得确定 GOOD/REVOKED 的依赖结果一律 fail-closed（依赖不可用），不伪装为吊销、不降级为通过。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PkiDeviceProofVerifier implements DeviceProofVerifier {

    /** 证明体上限（MTLS_CERT 可为叶子证书或完整链，≤16 KiB；实际状态查询只用叶子 DER ≤8 KiB） */
    private static final int MAX_CERT_DER_BYTES = 16 * 1024;
    /** 签名长度上限 */
    private static final int MAX_SIGNATURE_BYTES = 8 * 1024;

    private final CredentialEnrollmentRepository enrollmentRepository;
    private final CertificateVerificationAdapter certificateVerificationAdapter;
    private final CertEnrollmentAdapter certEnrollmentAdapter;

    @Override
    public DeviceProofEvidence verify(DeviceProofType proofType, byte[] proofBytes, String nonce, String deviceId,
                                      Instant verifiedAt) {
        if (proofType == null || proofBytes == null || proofBytes.length == 0) {
            throw new DeviceProofInvalidException("证明类型或证明体为空");
        }
        return switch (proofType) {
            case MTLS_CERT -> verifyMtlsCertificate(proofBytes, verifiedAt);
            case KEY_SIGNATURE -> verifyKeySignature(proofBytes, nonce, deviceId, verifiedAt);
        };
    }

    /**
     * MTLS_CERT：设备身份取自证书 Subject CN（= hsmUid），deviceId 不参与主体裁决。
     */
    private DeviceProofEvidence verifyMtlsCertificate(byte[] proofBytes, Instant verifiedAt) {
        if (proofBytes.length > MAX_CERT_DER_BYTES) {
            throw new DeviceProofInvalidException("证书链超过16KiB上限");
        }
        X509Certificate leaf = parseLeaf(proofBytes);
        String certSn = canonicalSerial(leaf);
        String fingerprint = fingerprint(leaf);

        CredentialEnrollment enrollment = enrollmentRepository.findByCertSn(certSn)
                .orElseThrow(() -> new DeviceProofInvalidException("证书未登记（certSn=" + certSn + "）"));
        requireActiveEnrollment(enrollment);
        requireFingerprintMatches(enrollment, fingerprint);

        String hsmUid = ViamUtils.normalizeUid(extractCommonName(leaf));
        if (hsmUid == null || !hsmUid.equals(ViamUtils.normalizeUid(enrollment.getHsmUid()))) {
            throw new DeviceProofInvalidException("证书CN与登记hsmUid不一致");
        }
        CertificateVerificationAdapter.CertificateVerificationResult result =
                verifyStatus(encoded(leaf), certSn, fingerprint, verifiedAt);
        Instant notAfter = leaf.getNotAfter() == null ? result.notAfter() : leaf.getNotAfter().toInstant();
        requireNotExpired(notAfter, verifiedAt);
        return new DeviceProofEvidence(hsmUid, certSn, fingerprint, enrollment.getDeviceSn(), notAfter, verifiedAt);
    }

    /**
     * KEY_SIGNATURE：deviceId 定位已登记 ACTIVE 证书；签名对象为 nonce 原文 UTF-8 字节。
     */
    private DeviceProofEvidence verifyKeySignature(byte[] signatureBytes, String nonce, String deviceId,
                                                   Instant verifiedAt) {
        if (signatureBytes.length > MAX_SIGNATURE_BYTES) {
            throw new DeviceProofInvalidException("签名超过8KiB上限");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new DeviceProofInvalidException("签名证明缺少nonce");
        }
        if (deviceId == null || deviceId.isBlank()) {
            throw new DeviceProofInvalidException("签名证明缺少deviceId，无法定位已登记证书");
        }
        CredentialEnrollment enrollment = resolveActiveEnrollment(deviceId.trim());
        byte[] leafDer = loadRegisteredLeaf(enrollment);
        X509Certificate leaf = parseLeaf(leafDer);
        String certSn = canonicalSerial(leaf);
        String fingerprint = fingerprint(leaf);
        requireFingerprintMatches(enrollment, fingerprint);
        String hsmUid = ViamUtils.normalizeUid(extractCommonName(leaf));
        if (hsmUid == null || !hsmUid.equals(ViamUtils.normalizeUid(enrollment.getHsmUid()))) {
            throw new DeviceProofInvalidException("证书CN与登记hsmUid不一致");
        }
        requireSignatureValid(leaf.getPublicKey(), nonce, signatureBytes);
        CertificateVerificationAdapter.CertificateVerificationResult result =
                verifyStatus(leafDer, certSn, fingerprint, verifiedAt);
        Instant notAfter = leaf.getNotAfter() == null ? result.notAfter() : leaf.getNotAfter().toInstant();
        requireNotExpired(notAfter, verifiedAt);
        return new DeviceProofEvidence(hsmUid, certSn, fingerprint, enrollment.getDeviceSn(), notAfter, verifiedAt);
    }

    /**
     * 定位已登记 ACTIVE 证书：deviceId 优先按 deviceSn（非证书设备业务标识），再按 hsmUid（证书设备唯一值）。
     * 命中多条视为歧义，拒绝（不猜测）。
     */
    private CredentialEnrollment resolveActiveEnrollment(String deviceId) {
        List<CredentialEnrollment> byDeviceSn = activeOnly(enrollmentRepository.listByDeviceSn(deviceId));
        if (byDeviceSn.size() == 1) {
            return byDeviceSn.get(0);
        }
        if (byDeviceSn.size() > 1) {
            throw new DeviceProofInvalidException("deviceId命中多条有效证书，拒绝猜测");
        }
        List<CredentialEnrollment> byHsmUid = activeOnly(
                enrollmentRepository.listByHsmUid(ViamUtils.normalizeUid(deviceId)));
        if (byHsmUid.size() == 1) {
            return byHsmUid.get(0);
        }
        if (byHsmUid.size() > 1) {
            throw new DeviceProofInvalidException("deviceId命中多条有效证书，拒绝猜测");
        }
        throw new DeviceProofInvalidException("deviceId未命中已登记证书");
    }

    private static List<CredentialEnrollment> activeOnly(List<CredentialEnrollment> enrollments) {
        if (enrollments == null) {
            return List.of();
        }
        return enrollments.stream()
                .filter(e -> e.getCertStatus() == CredentialEnrollment.CertificateState.ACTIVE)
                .toList();
    }

    /**
     * 经 PKI 申请编号重取已登记叶子证书（不落库、不缓存）。
     * <p>
     * step-ca 不提供按序列号回查能力，故只能按 {@code pkiRequestId} 走证书注册门面；
     * framework 判定「材料不可用/未就绪」归 {@code PROOF_INVALID}；
     * 存储、网络等真正的依赖故障归 {@code DEPENDENCY_UNAVAILABLE}，不把两者混为一谈。
     * </p>
     */
    private byte[] loadRegisteredLeaf(CredentialEnrollment enrollment) {
        String pkiRequestId = enrollment.getPkiRequestId();
        if (pkiRequestId == null || pkiRequestId.isBlank()) {
            throw new DeviceProofInvalidException("证书登记缺少PKI申请编号，无法取回证书材料");
        }
        IssuedCertificate issued;
        try {
            issued = certEnrollmentAdapter.getCertificate(pkiRequestId);
        } catch (CertificateMaterialUnavailableException | CertificateNotReadyException e) {
            throw new DeviceProofInvalidException("已登记证书材料不可再获取: " + brief(e), e);
        } catch (RuntimeException e) {
            throw new DeviceProofDependencyException("PKI证书材料获取失败: " + brief(e), e);
        }
        if (issued == null || issued.leafCertificate() == null || issued.leafCertificate().length == 0) {
            throw new DeviceProofInvalidException("已登记证书材料不可再获取（PKI无材料）");
        }
        return issued.leafCertificate();
    }

    /**
     * 异常摘要：单行、截断，便于日志定位且不放大异常正文。
     */
    private static String brief(Throwable e) {
        String message = e.getMessage();
        if (message == null || message.isBlank()) {
            return e.getClass().getSimpleName();
        }
        String singleLine = message.replaceAll("\\s+", " ").trim();
        String summary = singleLine.length() > 120 ? singleLine.substring(0, 120) + "..." : singleLine;
        return e.getClass().getSimpleName() + ": " + summary;
    }

    /**
     * 证书链/有效期/吊销：依赖 framework PKI 证书状态（OCSP 优先、CRL 兜底）。
     */
    private CertificateVerificationAdapter.CertificateVerificationResult verifyStatus(
            byte[] leafDer, String certSn, String fingerprint, Instant verifiedAt) {
        CertificateVerificationAdapter.CertificateVerificationResult result;
        try {
            result = certificateVerificationAdapter.verify(leafDer, certSn, fingerprint, verifiedAt);
        } catch (CertificateVerificationAdapter.ViamPkiDependencyUnavailable e) {
            throw new DeviceProofDependencyException("PKI证书状态不可用: " + e.getMessage(), e);
        }
        if (result.status() == CertificateStatus.REVOKED) {
            throw new DeviceProofInvalidException("证书已被吊销（certSn=" + certSn + "）");
        }
        if (result.status() != CertificateStatus.VALID) {
            throw new DeviceProofDependencyException("PKI证书状态不确定（" + result.status() + "），fail-closed");
        }
        return result;
    }

    private static void requireNotExpired(Instant notAfter, Instant verifiedAt) {
        if (notAfter != null && verifiedAt.isAfter(notAfter)) {
            throw new DeviceProofInvalidException("证书已过期");
        }
    }

    private static void requireFingerprintMatches(CredentialEnrollment enrollment, String fingerprint) {
        String registered = normalizeFingerprint(enrollment.getCertificateFingerprint());
        if (registered == null || !registered.equals(fingerprint)) {
            throw new DeviceProofInvalidException("证书指纹与登记事实不一致");
        }
    }

    /**
     * 只有 ACTIVE 登记证书可作为当前设备凭据；已作废/待确认/失败状态不得作为有效证明。
     */
    private static void requireActiveEnrollment(CredentialEnrollment enrollment) {
        if (enrollment.getCertStatus() != CredentialEnrollment.CertificateState.ACTIVE) {
            throw new DeviceProofInvalidException("证书登记状态非ACTIVE（" + enrollment.getCertStatus() + "）");
        }
    }

    private static void requireSignatureValid(PublicKey publicKey, String nonce, byte[] signatureBytes) {
        if (publicKey == null) {
            throw new DeviceProofInvalidException("已登记证书缺少公钥");
        }
        String algorithm = signatureAlgorithm(publicKey.getAlgorithm());
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(publicKey);
            signature.update(nonce.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (!signature.verify(signatureBytes)) {
                throw new DeviceProofInvalidException("nonce签名校验失败");
            }
        } catch (DeviceProofInvalidException e) {
            throw e;
        } catch (Exception e) {
            throw new DeviceProofInvalidException("nonce签名校验异常: " + e.getClass().getSimpleName(), e);
        }
    }

    private static String signatureAlgorithm(String keyAlgorithm) {
        String normalized = keyAlgorithm == null ? "" : keyAlgorithm.toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            case "ED25519", "EDDSA" -> "Ed25519";
            default -> throw new DeviceProofInvalidException("不支持的公钥类型: " + keyAlgorithm);
        };
    }

    /**
     * 解析叶子证书（支持 DER 单证书、DER 拼接链与 PEM；只取第一张）。
     */
    static X509Certificate parseLeaf(byte[] bytes) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> certs =
                    factory.generateCertificates(new ByteArrayInputStream(bytes));
            if (certs == null || certs.isEmpty()) {
                throw new DeviceProofInvalidException("证明体不包含可用证书");
            }
            java.security.cert.Certificate first = certs.iterator().next();
            if (!(first instanceof X509Certificate x509)) {
                throw new DeviceProofInvalidException("证明体不是X.509证书");
            }
            return x509;
        } catch (DeviceProofInvalidException e) {
            throw e;
        } catch (Exception e) {
            throw new DeviceProofInvalidException("证书解析失败: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * 提取 Subject CN（X500Principal 按 RFC 2253 逆序，需按段解析避免误取）。
     */
    static String extractCommonName(X509Certificate certificate) {
        String dn = certificate.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.regionMatches(true, 0, "CN=", 0, 3)) {
                return trimmed.substring(3).trim();
            }
        }
        return null;
    }

    static String canonicalSerial(X509Certificate certificate) {
        String serial = certificate.getSerialNumber() == null ? null : certificate.getSerialNumber().toString(16);
        return ViamUtils.canonicalCertSn(serial);
    }

    private static byte[] encoded(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (Exception e) {
            throw new DeviceProofInvalidException("证书DER读取失败", e);
        }
    }

    static String fingerprint(X509Certificate certificate) {
        try {
            return ViamUtils.sha256Hex(certificate.getEncoded());
        } catch (Exception e) {
            throw new DeviceProofInvalidException("证书编码读取失败", e);
        }
    }

    private static String normalizeFingerprint(String fingerprint) {
        if (fingerprint == null) {
            return null;
        }
        String normalized = fingerprint.replace(":", "").replace(" ", "").trim().toLowerCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }
}
