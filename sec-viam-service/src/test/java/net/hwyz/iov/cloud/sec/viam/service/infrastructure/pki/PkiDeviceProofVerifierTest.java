package net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofType;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofInvalidException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofEvidence;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 设备证明校验适配器单元测试（SEC-VIAM-DSN-CR-003 / TC-VIAM-3-01～03）。
 * <p>
 * 使用真实 EC 密钥与自签证书做真实验签/解析；PKI 证书状态与仓储以 Mock 注入，
 * 覆盖：有效证明、指纹不符、吊销、未知、过期、未登记、签名不匹配、PKI 不可用。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class PkiDeviceProofVerifierTest {

    private static final String UID = "HSM-0001";
    private static final String SN = "SN-0001";
    private static final String NONCE = "nonce-0123456789abcdef";

    @Mock
    private CredentialEnrollmentRepository enrollmentRepository;
    @Mock
    private CertificateVerificationAdapter certificateVerificationAdapter;
    @Mock
    private ObjectProvider<PkiClient> pkiClientProvider;

    private PkiDeviceProofVerifier verifier;

    private KeyPair keyPair;
    private X509Certificate certificate;
    private byte[] leafDer;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new PkiDeviceProofVerifier(enrollmentRepository, certificateVerificationAdapter, pkiClientProvider);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        keyPair = generator.generateKeyPair();
        certificate = selfSigned(keyPair, UID, BigInteger.valueOf(0x0a1b2cL), 24L);
        leafDer = certificate.getEncoded();
    }

    private static X509Certificate selfSigned(KeyPair keyPair, String cn, BigInteger serial, long validHours)
            throws Exception {
        long now = System.currentTimeMillis();
        X500Name name = new X500Name("CN=" + cn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, new Date(now - 60_000L), new Date(now + validHours * 3_600_000L), name,
                keyPair.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    private CredentialEnrollment enrollment(String certSn, String fingerprint,
                                            CredentialEnrollment.CertificateState state) {
        return CredentialEnrollment.builder()
                .requestId("REQ-1")
                .deviceSn(SN)
                .hsmUid(UID)
                .certSn(certSn)
                .certificateFingerprint(fingerprint)
                .certStatus(state)
                .build();
    }

    private String serial() {
        return ViamUtils.canonicalCertSn(certificate.getSerialNumber().toString(16));
    }

    private String fingerprint() throws Exception {
        return ViamUtils.sha256Hex(certificate.getEncoded());
    }

    private void registered() throws Exception {
        when(enrollmentRepository.findByCertSn(serial()))
                .thenReturn(Optional.of(enrollment(serial(), fingerprint(), CredentialEnrollment.CertificateState.ACTIVE)));
    }

    private void status(CertificateStatus status) throws Exception {
        lenient().when(certificateVerificationAdapter.verify(any(byte[].class), anyString(), anyString(), any()))
                .thenReturn(new CertificateVerificationAdapter.CertificateVerificationResult(
                        status, UID, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-01 有效 mTLS 证书（链/有效期/吊销通过 + 指纹登记一致）→ 返回已登记证据")
    void validMtlsCertificate() throws Exception {
        registered();
        status(CertificateStatus.VALID);

        DeviceProofEvidence evidence = verifier.verify(DeviceProofType.MTLS_CERT, leafDer, NONCE, null, Instant.now());

        assertEquals(UID, evidence.hsmUid());
        assertEquals(serial(), evidence.certSn());
        assertEquals(SN, evidence.deviceSn());
        assertEquals(fingerprint(), evidence.fingerprint());
        assertNotNull(evidence.verifiedAt());
    }

    @Test
    @DisplayName("TC-VIAM-3-02 指纹与登记事实不一致 → PROOF_INVALID")
    void fingerprintMismatch() throws Exception {
        when(enrollmentRepository.findByCertSn(serial()))
                .thenReturn(Optional.of(enrollment(serial(), "deadbeef", CredentialEnrollment.CertificateState.ACTIVE)));

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, leafDer, NONCE, null, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-02 证书未登记 → PROOF_INVALID")
    void unregisteredCertificate() {
        when(enrollmentRepository.findByCertSn(serial())).thenReturn(Optional.empty());

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, leafDer, NONCE, null, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-02 已吊销 → PROOF_INVALID")
    void revokedCertificate() throws Exception {
        registered();
        status(CertificateStatus.REVOKED);

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, leafDer, NONCE, null, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-02 证书状态未知 → DEPENDENCY_UNAVAILABLE（fail-closed，不伪装为吊销）")
    void unknownStatusFailClosed() throws Exception {
        registered();
        status(CertificateStatus.UNKNOWN);

        assertThrows(DeviceProofDependencyException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, leafDer, NONCE, null, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-02 证书已过期 → PROOF_INVALID")
    void expiredCertificate() throws Exception {
        X509Certificate expired = selfSigned(keyPair, UID, BigInteger.valueOf(0x0a1b2dL), 0L);
        byte[] expiredDer = expired.getEncoded();
        String expiredSn = ViamUtils.canonicalCertSn(expired.getSerialNumber().toString(16));
        when(enrollmentRepository.findByCertSn(expiredSn)).thenReturn(Optional.of(enrollment(expiredSn,
                ViamUtils.sha256Hex(expiredDer), CredentialEnrollment.CertificateState.ACTIVE)));
        lenient().when(certificateVerificationAdapter.verify(any(byte[].class), anyString(), anyString(), any()))
                .thenReturn(new CertificateVerificationAdapter.CertificateVerificationResult(
                        CertificateStatus.VALID, UID, Instant.now().minusSeconds(120), Instant.now().minusSeconds(60),
                        Instant.now()));

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, expiredDer, NONCE, null, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-02 登记状态非 ACTIVE（作废/待确认）→ PROOF_INVALID")
    void nonActiveEnrollment() throws Exception {
        when(enrollmentRepository.findByCertSn(serial())).thenReturn(Optional.of(
                enrollment(serial(), fingerprint(), CredentialEnrollment.CertificateState.SUPERSEDED)));

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, leafDer, NONCE, null, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-01 KEY_SIGNATURE：公钥验签 nonce 成功 → 返回已登记证据")
    void validKeySignature() throws Exception {
        when(enrollmentRepository.listByDeviceSn(SN))
                .thenReturn(List.of(enrollment(serial(), fingerprint(), CredentialEnrollment.CertificateState.ACTIVE)));
        PkiClient pkiClient = mock(PkiClient.class);
        when(pkiClientProvider.getIfAvailable()).thenReturn(pkiClient);
        when(pkiClient.queryCertificate(serial()))
                .thenReturn(new PkiClient.CertificateResponse("PKI-1", leafDer, leafDer, serial(), null, null));
        status(CertificateStatus.VALID);

        byte[] signature = sign(NONCE);
        DeviceProofEvidence evidence = verifier.verify(DeviceProofType.KEY_SIGNATURE, signature, NONCE, SN,
                Instant.now());

        assertEquals(UID, evidence.hsmUid());
        assertEquals(SN, evidence.deviceSn());
    }

    @Test
    @DisplayName("TC-VIAM-3-02 KEY_SIGNATURE：签名与 nonce 不匹配 → PROOF_INVALID")
    void keySignatureMismatch() throws Exception {
        when(enrollmentRepository.listByDeviceSn(SN))
                .thenReturn(List.of(enrollment(serial(), fingerprint(), CredentialEnrollment.CertificateState.ACTIVE)));
        PkiClient pkiClient = mock(PkiClient.class);
        when(pkiClientProvider.getIfAvailable()).thenReturn(pkiClient);
        when(pkiClient.queryCertificate(serial()))
                .thenReturn(new PkiClient.CertificateResponse("PKI-1", leafDer, leafDer, serial(), null, null));

        byte[] wrongSignature = sign("another-nonce-value");

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.KEY_SIGNATURE, wrongSignature, NONCE, SN, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-02 KEY_SIGNATURE：deviceId 未命中已登记证书 → PROOF_INVALID")
    void keySignatureUnknownDevice() {
        when(enrollmentRepository.listByDeviceSn(SN)).thenReturn(List.of());
        when(enrollmentRepository.listByHsmUid(SN)).thenReturn(List.of());

        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.KEY_SIGNATURE, new byte[]{1, 2, 3}, NONCE, SN, Instant.now()));
    }

    @Test
    @DisplayName("TC-VIAM-3-04 KEY_SIGNATURE：PKI 无法重取证书 → DEPENDENCY_UNAVAILABLE")
    void keySignaturePkiUnavailable() throws Exception {
        when(enrollmentRepository.listByDeviceSn(SN))
                .thenReturn(List.of(enrollment(serial(), fingerprint(), CredentialEnrollment.CertificateState.ACTIVE)));
        PkiClient pkiClient = mock(PkiClient.class);
        when(pkiClientProvider.getIfAvailable()).thenReturn(pkiClient);
        when(pkiClient.queryCertificate(serial())).thenThrow(new IllegalStateException("pki down"));

        assertThrows(DeviceProofDependencyException.class,
                () -> verifier.verify(DeviceProofType.KEY_SIGNATURE, new byte[]{1, 2, 3}, NONCE, SN, Instant.now()));
    }

    @Test
    @DisplayName("PKI 见证后不复用目录替代：证书解析失败即为 PROOF_INVALID")
    void unparsableProof() {
        assertThrows(DeviceProofInvalidException.class,
                () -> verifier.verify(DeviceProofType.MTLS_CERT, "not-a-cert".getBytes(StandardCharsets.UTF_8),
                        NONCE, null, Instant.now()));
    }

    private byte[] sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate(), new SecureRandom());
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }
}
