package net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki;

import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.SubjectRef;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.CsrTestSupport;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 证书注册适配器测试（SEC-VIAM-DSN-CR-004 / D-VIAM-025 / T26、T27）。
 * <p>
 * 覆盖：IVI/TBOX Profile 提交属性、SubjectRef 保持 DEVICE_UID、IVI 签发后
 * Profile（702217）/CN（702218）/SPKI（702219）复验、UNKNOWN 转待对账、
 * TBOX 签发路径行为不变（不做 IVI 专属复验）。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SEC-VIAM-DSN-CR-004 证书注册适配器")
class CertEnrollmentAdapterTest {

    private static final String IVI_CN = "UID-IVI";
    private static final String TBOX_CN = "UID-TBOX";

    @Mock
    private CertEnrollmentTemplate template;

    @Mock
    private ObjectProvider<CertEnrollmentTemplate> templateProvider;

    private CertEnrollmentAdapter adapter;

    @BeforeEach
    void setUp() {
        lenient().when(templateProvider.getIfAvailable()).thenReturn(template);
        adapter = new CertEnrollmentAdapter(templateProvider);
    }

    // ==================== 提交属性 ====================

    @Test
    @DisplayName("T26 IVI 提交 EC P-256 + digitalSignature/clientAuth，主体保持 DEVICE_UID=hsmUid")
    void iviProfileSubmittedWithGovernedAttributes() {
        KeyPair keyPair = CsrTestSupport.keyPair();
        String csr = CsrTestSupport.csr(new X500Name("CN=" + IVI_CN), keyPair);
        CredentialEnrollment enrollment = enrollment("IVI_DEVICE_IDENTITY", IVI_CN);
        givenIssued(enrollment, keyPair, IVI_CN, true, false);

        adapter.apply(enrollment, csr);

        ArgumentCaptor<CertApplyRequest> captor = ArgumentCaptor.forClass(CertApplyRequest.class);
        verify(template).apply(captor.capture());
        CertApplyRequest request = captor.getValue();
        assertEquals("IVI_DEVICE_IDENTITY", request.certificateProfile().name());
        assertEquals("EC_P256", request.certificateProfile().allowedAlgorithm());
        assertEquals("DIGITAL_SIGNATURE,CLIENT_AUTH", request.certificateProfile().usage());
        assertEquals(SubjectRef.SubjectType.DEVICE_UID, request.subject().type());
        assertEquals(IVI_CN, request.subject().value());
        assertEquals(enrollment.getRequestId(), request.idempotencyKey());
        assertEquals(CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED, enrollment.getCertStatus());
        assertEquals("abc123", enrollment.getCertSn());
    }

    @Test
    @DisplayName("T30 TBOX 提交属性与 Subject 行为不变（ECDSA / DIGITAL_SIGNATURE,KEY_AGREEMENT）")
    void tboxProfileKeepsLegacyAttributes() {
        KeyPair keyPair = CsrTestSupport.keyPair();
        String csr = CsrTestSupport.csr(new X500Name("CN=" + TBOX_CN), keyPair);
        CredentialEnrollment enrollment = enrollment("TBOX_TSP_CLIENT", TBOX_CN);
        givenIssued(enrollment, keyPair, TBOX_CN, true, false);

        adapter.apply(enrollment, csr);

        ArgumentCaptor<CertApplyRequest> captor = ArgumentCaptor.forClass(CertApplyRequest.class);
        verify(template).apply(captor.capture());
        assertEquals("ECDSA", captor.getValue().certificateProfile().allowedAlgorithm());
        assertEquals("DIGITAL_SIGNATURE,KEY_AGREEMENT",
                captor.getValue().certificateProfile().usage());
        assertEquals(SubjectRef.SubjectType.DEVICE_UID, captor.getValue().subject().type());
    }

    // ==================== IVI 签发后复验 ====================

    @Test
    @DisplayName("T27 IVI 签发结果为 CA 证书时以 702217 拒绝")
    void iviCaLeafRejected() {
        assertIviRejected(ViamErrorCode.CERTIFICATE_ISSUED_PROFILE_MISMATCH,
                IVI_CN, true, true, IVI_CN);
    }

    @Test
    @DisplayName("T27 IVI 签发结果缺 clientAuth 时以 702217 拒绝")
    void iviMissingClientAuthRejected() {
        assertIviRejected(ViamErrorCode.CERTIFICATE_ISSUED_PROFILE_MISMATCH,
                IVI_CN, false, false, IVI_CN);
    }

    @Test
    @DisplayName("T27 IVI 签发结果 CN 不等于 hsmUid 时以 702218 拒绝")
    void iviCnMismatchRejected() {
        assertIviRejected(ViamErrorCode.CERTIFICATE_UID_BINDING_MISMATCH,
                IVI_CN, true, false, "UID-OTHER");
    }

    @Test
    @DisplayName("T27 IVI 签发结果公钥与 CSR 公钥不一致时以 702219 拒绝")
    void iviSpkiMismatchRejected() {
        KeyPair csrKeyPair = CsrTestSupport.keyPair();
        String csr = CsrTestSupport.csr(new X500Name("CN=" + IVI_CN), csrKeyPair);
        CredentialEnrollment enrollment = enrollment("IVI_DEVICE_IDENTITY", IVI_CN);
        // 证书由另一把密钥签发：CN/clientAuth 均正确，仅 SPKI 不匹配
        givenIssued(enrollment, CsrTestSupport.keyPair(), IVI_CN, true, false);

        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> adapter.apply(enrollment, csr));
        assertEquals(ViamErrorCode.CERTIFICATE_PUBLIC_KEY_BINDING_MISMATCH.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T30 TBOX 签发路径不做 IVI 专属复验（CN 为 deviceSn 的历史行为保持不变）")
    void tboxIssuanceSkipsIviOnlyChecks() {
        KeyPair keyPair = CsrTestSupport.keyPair();
        String csr = CsrTestSupport.csr(new X500Name("CN=" + TBOX_CN), keyPair);
        CredentialEnrollment enrollment = enrollment("TBOX_TSP_CLIENT", TBOX_CN);
        givenIssued(enrollment, keyPair, "SN-TBOX", true, false);

        adapter.apply(enrollment, csr);

        assertEquals(CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED, enrollment.getCertStatus());
    }

    // ==================== 结果未知与 Profile 放行 ====================

    @Test
    @DisplayName("T27 结果未知转 PENDING_RECONCILE，禁止自动重签")
    void unknownOutcomeMovesToPendingReconcile() {
        CredentialEnrollment enrollment = enrollment("IVI_DEVICE_IDENTITY", IVI_CN);
        when(template.apply(any())).thenReturn(
                new CertApplyResult(enrollment.getRequestId(), EnrollmentState.UNKNOWN, Instant.now()));

        adapter.apply(enrollment, CsrTestSupport.csr(new X500Name("CN=" + IVI_CN), CsrTestSupport.keyPair()));

        assertEquals(CredentialEnrollment.CertificateState.PENDING_RECONCILE, enrollment.getCertStatus());
        assertEquals(enrollment.getRequestId(), enrollment.getPkiRequestId());
    }

    @Test
    @DisplayName("T27 framework 未登记该 Profile 时抛 CertificateProfileNotAllowedException（由应用层映射 702207）")
    void unregisteredProfileBubblesFrameworkRejection() {
        CredentialEnrollment enrollment = enrollment("IVI_DEVICE_IDENTITY", IVI_CN);
        when(template.apply(any())).thenThrow(new CertificateProfileNotAllowedException("not allowed"));

        assertThrows(CertificateProfileNotAllowedException.class,
                () -> adapter.apply(enrollment,
                        CsrTestSupport.csr(new X500Name("CN=" + IVI_CN), CsrTestSupport.keyPair())));
    }

    // ==================== 夹具 ====================

    private void assertIviRejected(ViamErrorCode expected, String subjectCn,
                                   boolean clientAuth, boolean ca, String leafCn) {
        KeyPair keyPair = CsrTestSupport.keyPair();
        String csr = CsrTestSupport.csr(new X500Name("CN=" + subjectCn), keyPair);
        CredentialEnrollment enrollment = enrollment("IVI_DEVICE_IDENTITY", subjectCn);
        givenIssued(enrollment, keyPair, leafCn, clientAuth, ca);

        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> adapter.apply(enrollment, csr));
        assertEquals(expected.getCode(), ex.getCode());
    }

    private void givenIssued(CredentialEnrollment enrollment, KeyPair leafKeyPair, String leafCn,
                             boolean clientAuth, boolean ca) {
        when(template.apply(any())).thenReturn(
                new CertApplyResult(enrollment.getRequestId(), EnrollmentState.ISSUED, Instant.now()));
        byte[] leafDer = leaf(leafKeyPair, leafCn, clientAuth, ca);
        when(template.getCertificate(anyString())).thenReturn(new IssuedCertificate(
                leafDer, List.of(leafDer), "abc123", Instant.now(),
                Instant.now().plusSeconds(86400), "fp"));
    }

    private static CredentialEnrollment enrollment(String profile, String hsmUid) {
        return CredentialEnrollment.builder()
                .requestId("REQ-1").vin("VIN1").deviceSn("SN-1")
                .deviceCategory(profile.startsWith("IVI") ? "IVI" : "TBOX")
                .hsmUid(hsmUid).certificateProfile(profile)
                .certStatus(CredentialEnrollment.CertificateState.REQUESTED)
                .build();
    }

    /**
     * 生成自签叶子证书（仅用于适配器复验：CN / EKU / CA 属性可参数化）。
     */
    private static byte[] leaf(KeyPair keyPair, String cn, boolean clientAuth, boolean ca) {
        try {
            long now = System.currentTimeMillis();
            X500Name name = new X500Name("CN=" + cn);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    name, BigInteger.valueOf(now), new Date(now - 60_000L),
                    new Date(now + 3_600_000L), name, keyPair.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            if (clientAuth) {
                builder.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            }
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                            .build(keyPair.getPrivate())));
            return certificate.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("测试叶子证书生成失败", e);
        }
    }
}
