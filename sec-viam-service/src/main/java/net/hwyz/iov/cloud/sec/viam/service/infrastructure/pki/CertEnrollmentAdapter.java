package net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.SubjectRef;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.CertificateCompensationPolicy;
import net.hwyz.iov.cloud.sec.viam.service.common.util.CertificateCsrValidator;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * FW-SEC CertEnrollmentTemplate 证书注册适配器（SEC-VIAM-DSN-CR-001 / D-VIAM-006 / FR-VIAM-002）
 * <p>
 * 保留现行证书逻辑 Profile、CSR/leaf SPKI 及 CN 校验、用途/信任链/有效期/吊销与
 * 签发后 Profile 复验；结果未知（PkiOutcomeUnknown）转 PENDING_RECONCILE 禁止自动重签。
 * </p>
 * <p>
 * SEC-VIAM-DSN-CR-004 / D-VIAM-025：按 Profile 提交受治理的属性（TBOX 保持原值；
 * IVI 使用 EC P-256 + digitalSignature/clientAuth），并在 IVI 签发后复验 Profile（CA=false、
 * clientAuth，702217）、CN=规范化 hsmUid（702218）与 leaf 公钥=CSR 公钥（702219）。
 * 主体仍固定 {@code SubjectRef(DEVICE_UID, hsmUid)}，IVI 不切换 DEVICE_SN。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertEnrollmentAdapter {

    private final ObjectProvider<CertEnrollmentTemplate> templateProvider;

    /**
     * 提交证书申请（同步签发路径）。
     *
     * @param enrollment    证书记录（须已落库 REQUESTED）
     * @param csrDerBase64  CSR DER Base64
     */
    public void apply(CredentialEnrollment enrollment, String csrDerBase64) {
        CertEnrollmentTemplate template = requireTemplate();
        // 统一归一化（PEM/Base64URL/带空白均接受）；非法编码归为 702204，不冒泡为系统异常
        byte[] csr = Base64.getDecoder().decode(CertificateCsrValidator.toStandardBase64(csrDerBase64));
        CertApplyRequest request = new CertApplyRequest(
                profileOf(enrollment.getCertificateProfile()),
                csr,
                new SubjectRef(SubjectRef.SubjectType.DEVICE_UID, enrollment.getHsmUid()),
                enrollment.getRequestId(),
                null);
        CertApplyResult result = template.apply(request);
        enrollment.setPkiRequestId(result.requestId());
        switch (result.state()) {
            case ISSUED -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUING);
                IssuedCertificate issued = template.getCertificate(result.requestId());
                if (issued != null) {
                    markIssuedFromTemplate(enrollment, issued, csr);
                }
            }
            case REJECTED, FAILED -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.FAILED);
                enrollment.setFailReason("PKI拒绝或失败: " + result.state());
            }
            case UNKNOWN -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.PENDING_RECONCILE);
                enrollment.setFailReason("PKI结果未知: " + result.state());
            }
            default -> enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUING);
        }
    }

    /**
     * 按 PKI 申请编号重取已签发证书（SEC-VIAM-DSN-CR-002 / D-VIAM-015）。
     * <p>
     * 只读操作：仅用于管理面「获取证书本体」，不改状态、不落库、不缓存。
     * PKI 已不保留该申请材料时返回 null，由调用方给出明确失败，不伪造成功。
     * </p>
     *
     * @param pkiRequestId PKI 申请编号
     * @return 已签发证书（含叶子与链 DER），不可获取时为 null
     */
    public IssuedCertificate getCertificate(String pkiRequestId) {
        if (pkiRequestId == null || pkiRequestId.isBlank()) {
            return null;
        }
        return requireTemplate().getCertificate(pkiRequestId);
    }

    /**
     * 对账推进（getStatus/getCertificate）。
     */
    public void reconcile(CredentialEnrollment enrollment) {
        CertEnrollmentTemplate template = requireTemplate();
        CertApplyResult status = template.getStatus(enrollment.getPkiRequestId());
        switch (status.state()) {
            case ISSUED -> {
                IssuedCertificate issued = template.getCertificate(enrollment.getPkiRequestId());
                if (issued != null) {
                    // 对账路径无 CSR 原文：SPKI 一致性由 FW-SEC 结果存储中的原 CSR 保证
                    markIssuedFromTemplate(enrollment, issued, null);
                }
            }
            case REJECTED, FAILED -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.FAILED);
                enrollment.setFailReason("PKI拒绝或失败: " + status.state());
            }
            case UNKNOWN -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.PENDING_RECONCILE);
                enrollment.setFailReason("PKI结果未知: " + status.state());
            }
            default -> enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUING);
        }
    }

    /**
     * 从模板 IssuedCertificate 登记证书元数据（签发后复验语义由模板校验保证）。
     */
    private void markIssuedFromTemplate(CredentialEnrollment enrollment, IssuedCertificate issued, byte[] csrDer) {
        enrollment.setCertSn(ViamUtils.canonicalCertSn(issued.serialNumber()));
        enrollment.setCertificateFingerprint(issued.sha256Fingerprint());
        enrollment.setNotBefore(issued.notBefore());
        enrollment.setNotAfter(issued.notAfter());
        enrollment.setIssuedAt(java.time.Instant.now());
        enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED);
        if (isIviProfile(enrollment.getCertificateProfile())) {
            verifyIviIssuedBinding(enrollment, issued, csrDer);
        }
    }

    /**
     * IVI 签发后绑定复验（D-VIAM-025）：Profile 特征 → CN → SPKI，确定性拒绝，不伪成功。
     */
    private void verifyIviIssuedBinding(CredentialEnrollment enrollment, IssuedCertificate issued, byte[] csrDer) {
        X509Certificate leaf = parseLeaf(issued);
        if (leaf.getBasicConstraints() >= 0 || !hasClientAuthEku(leaf)) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_ISSUED_PROFILE_MISMATCH);
        }
        List<String> commonNames = subjectCommonNames(leaf);
        String expectedCn = ViamUtils.normalizeUid(enrollment.getHsmUid());
        if (commonNames.size() != 1 || expectedCn == null
                || !expectedCn.equals(ViamUtils.normalizeUid(commonNames.get(0)))) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_UID_BINDING_MISMATCH);
        }
        if (csrDer != null && !spkiMatchesCsr(leaf, csrDer)) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_PUBLIC_KEY_BINDING_MISMATCH);
        }
    }

    /**
     * 解析叶子证书；失败按 Profile 复验失败的确定性拒绝处理。
     */
    private static X509Certificate parseLeaf(IssuedCertificate issued) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(issued.leafCertificate()));
        } catch (CertificateException e) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_ISSUED_PROFILE_MISMATCH,
                    "签发结果叶子证书无法解析");
        }
    }

    /**
     * 叶子证书是否声明 clientAuth 扩展密钥用法。
     */
    private static boolean hasClientAuthEku(X509Certificate leaf) {
        try {
            List<String> eku = leaf.getExtendedKeyUsage();
            if (eku == null) {
                return false;
            }
            for (String value : eku) {
                if ("1.3.6.1.5.5.7.3.2".equals(value) || "clientAuth".equalsIgnoreCase(value)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 叶子证书 Subject 中的全部 CN（保持顺序、不去重）。
     */
    private static List<String> subjectCommonNames(X509Certificate leaf) {
        try {
            X500Name subject = new JcaX509CertificateHolder(leaf).getSubject();
            List<String> values = new ArrayList<>();
            for (RDN rdn : subject.getRDNs(BCStyle.CN)) {
                values.add(rdn.getFirst().getValue().toString());
            }
            return values;
        } catch (Exception e) {
            return List.of();
        }
    }

    /**
     * 叶子证书公钥是否与 CSR 公钥一致（仅当本路径持有 CSR 原文时执行）。
     */
    private static boolean spkiMatchesCsr(X509Certificate leaf, byte[] csrDer) {
        try {
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csrDer);
            PublicKey csrPublicKey = new JcaPEMKeyConverter().getPublicKey(request.getSubjectPublicKeyInfo());
            return MessageDigest.isEqual(csrPublicKey.getEncoded(), leaf.getPublicKey().getEncoded());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 受治理 Profile 对应的提交属性（D-VIAM-025）。
     * <p>
     * TBOX_TSP_CLIENT 与未登记名称保持既有取值（ECDSA / DIGITAL_SIGNATURE,KEY_AGREEMENT），
     * 白名单仍由 FW-SEC 判定；IVI_DEVICE_IDENTITY 使用 EC P-256 + digitalSignature/clientAuth，
     * 不复用 TBOX 的 ECDH/Keyprov 用途。
     * </p>
     */
    private static CertificateProfile profileOf(String certificateProfile) {
        String normalized = CertificateCompensationPolicy.normalize(certificateProfile);
        if (CertificateCompensationPolicy.PROFILE_IVI.equals(normalized)) {
            return new CertificateProfile(
                    certificateProfile,
                    certificateProfile,
                    CertificateProfile.SubjectType.DEVICE_IDENTITY,
                    "EC_P256",
                    "DIGITAL_SIGNATURE,CLIENT_AUTH");
        }
        return new CertificateProfile(
                certificateProfile,
                certificateProfile,
                CertificateProfile.SubjectType.DEVICE_IDENTITY,
                "ECDSA",
                "DIGITAL_SIGNATURE,KEY_AGREEMENT");
    }

    /**
     * 是否为 IVI 设备身份证书 Profile。
     */
    private static boolean isIviProfile(String certificateProfile) {
        return CertificateCompensationPolicy.PROFILE_IVI
                .equals(CertificateCompensationPolicy.normalize(certificateProfile));
    }

    private CertEnrollmentTemplate requireTemplate() {
        return Optional.ofNullable(templateProvider.getIfAvailable())
                .orElseThrow(() -> new IllegalStateException("PKI证书注册模板未装配（PKI服务不可用）"));
    }
}
