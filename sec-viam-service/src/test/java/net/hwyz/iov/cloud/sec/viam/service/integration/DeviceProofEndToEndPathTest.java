package net.hwyz.iov.cloud.sec.viam.service.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofReasonCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofType;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service.ServiceDeviceProofController;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.security.WorkloadContext;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.security.WorkloadContextHolder;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceProofVerifyAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofAuditRecorder;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofMetrics;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofNonceStore;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofProperties;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofRateLimiter;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertificateVerificationAdapter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.PkiDeviceProofVerifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 设备证明校验全链路路径测试（SEC-VIAM-DSN-CR-003 / TC-VIAM-3-01～06）。
 * <p>
 * 链路：{@link ServiceDeviceProofController} → {@link DeviceProofVerifyAppService} →
 * {@link PkiDeviceProofVerifier}（真实证书解析/状态映射）→ 仓储与 PKI 边界（Mock）。
 * Redis 以内存 Map 模拟 SETNX/INCR，验证 nonce 一次性、限流、审计脱敏与只读幂等。
 * 无真实 DB/Redis/PKI/Kafka 环境，不代表生产验证通过。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DeviceProofEndToEndPathTest {

    private static final String UID = "HSM-0001";
    private static final String PRINCIPAL_ID = "PR-0001";
    private static final String SN = "SN-0001";
    private static final String VIN = "VIN0000000000001";

    @Mock
    private CredentialEnrollmentRepository enrollmentRepository;
    @Mock
    private SecurityPrincipalRepository principalRepository;
    @Mock
    private PrincipalAssetMappingRepository mappingRepository;
    @Mock
    private DeviceOnboardingRepository onboardingRepository;
    @Mock
    private SecurityOperationAuditRepository auditRepository;
    @Mock
    private CertificateVerificationAdapter certificateVerificationAdapter;
    @Mock
    private ObjectProvider<net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient> pkiClientProvider;
    @Mock
    private StringRedisTemplate stringRedisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private final Map<String, String> redis = new HashMap<>();

    private ServiceDeviceProofController controller;

    private X509Certificate certificate;
    private byte[] leafDer;
    private String certSn;

    @BeforeEach
    void setUp() throws Exception {
        DeviceProofProperties properties = new DeviceProofProperties();

        stubRedis();
        DeviceProofNonceStore nonceStore = new DeviceProofNonceStore(stringRedisTemplate, properties);
        DeviceProofRateLimiter rateLimiter = new DeviceProofRateLimiter(stringRedisTemplate, properties);
        DeviceProofAuditRecorder auditRecorder = new DeviceProofAuditRecorder(auditRepository, new ObjectMapper());
        @SuppressWarnings("unchecked")
        ObjectProvider<MeterRegistry> registryProvider = mock(ObjectProvider.class);
        when(registryProvider.getIfAvailable()).thenReturn(new SimpleMeterRegistry());
        DeviceProofMetrics metrics = new DeviceProofMetrics(registryProvider);

        PkiDeviceProofVerifier verifier =
                new PkiDeviceProofVerifier(enrollmentRepository, certificateVerificationAdapter, pkiClientProvider);
        DeviceProofVerifyAppService appService = new DeviceProofVerifyAppService(verifier, principalRepository,
                mappingRepository, onboardingRepository, nonceStore, rateLimiter, auditRecorder, metrics, properties);
        controller = new ServiceDeviceProofController(appService);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name name = new X500Name("CN=" + UID);
        long now = System.currentTimeMillis();
        certificate = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(0x0a1b2cL),
                                new Date(now - 60_000L), new Date(now + 3_600_000L), name, keyPair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
        leafDer = certificate.getEncoded();
        certSn = ViamUtils.canonicalCertSn(certificate.getSerialNumber().toString(16));

        WorkloadContextHolder.set(new WorkloadContext("CIAM", "/api/service/deviceProof/v1/verify"));
    }

    @AfterEach
    void tearDown() {
        WorkloadContextHolder.clear();
    }

    private void stubRedis() {
        lenient().when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        lenient().when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class)))
                .thenAnswer(invocation -> redis.putIfAbsent(invocation.getArgument(0), "1") == null);
        lenient().when(valueOperations.increment(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            long next = Long.parseLong(redis.getOrDefault(key, "0")) + 1;
            redis.put(key, String.valueOf(next));
            return next;
        });
        lenient().when(stringRedisTemplate.expire(anyString(), anyLong(), any(TimeUnit.class))).thenReturn(true);
    }

    private void stubActiveDevice() throws Exception {
        String fingerprint = ViamUtils.sha256Hex(leafDer);
        when(enrollmentRepository.findByCertSn(certSn)).thenReturn(Optional.of(CredentialEnrollment.builder()
                .requestId("REQ-1")
                .deviceSn(SN)
                .hsmUid(UID)
                .certSn(certSn)
                .certificateFingerprint(fingerprint)
                .certStatus(CredentialEnrollment.CertificateState.ACTIVE)
                .build()));
        lenient().when(certificateVerificationAdapter.verify(any(byte[].class), anyString(), anyString(), any()))
                .thenReturn(new CertificateVerificationAdapter.CertificateVerificationResult(
                        CertificateStatus.VALID, UID, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
                        Instant.now()));
        when(principalRepository.findByHsmUid(UID)).thenReturn(Optional.of(SecurityPrincipal.builder()
                .principalId(PRINCIPAL_ID).hsmUid(UID).state(SecurityPrincipal.PrincipalState.ACTIVE).build()));
        when(mappingRepository.listActiveByPrincipalId(PRINCIPAL_ID)).thenReturn(List.of(PrincipalAssetMapping.builder()
                .principalId(PRINCIPAL_ID).vin(VIN).deviceSn(SN).state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build()));
        when(onboardingRepository.findByPrincipalId(PRINCIPAL_ID)).thenReturn(Optional.of(DeviceOnboarding.builder()
                .principalId(PRINCIPAL_ID).hsmUid(UID).deviceSn(SN)
                .state(DeviceOnboarding.OnboardingState.ACTIVE).build()));
    }

    private DeviceProofVerifyRequestVo request(String nonce) {
        return DeviceProofVerifyRequestVo.builder()
                .proofType(DeviceProofType.MTLS_CERT.name())
                .proof(java.util.Base64.getEncoder().encodeToString(leafDer))
                .nonce(nonce)
                .build();
    }

    @Test
    @DisplayName("TC-VIAM-3-01 有效证明全链路：valid=true + 主体/SN/状态，且不返回 VIN")
    void validProofEndToEnd() throws Exception {
        stubActiveDevice();

        DeviceProofVerifyResultVo result = controller.verify(request("nonce-endtoend-00001"));

        assertTrue(result.isValid());
        assertEquals(DeviceProofReasonCode.PROOF_VALID.name(), result.getReasonCode());
        assertEquals(PRINCIPAL_ID, result.getDevicePrincipal());
        assertEquals(SN, result.getDeviceSn());
        assertEquals("ACTIVE", result.getDeviceStatus());
        assertNotNull(result.getVerifiedAt());

        ArgumentCaptor<SecurityOperationAudit> captor = ArgumentCaptor.forClass(SecurityOperationAudit.class);
        verify(auditRepository).save(captor.capture());
        String detail = captor.getValue().getDetail();
        assertTrue(detail.contains("\"reasonCode\":\"PROOF_VALID\""));
        assertFalse(detail.contains(java.util.Base64.getEncoder().encodeToString(leafDer)));
        assertFalse(detail.contains(VIN));
    }

    @Test
    @DisplayName("TC-VIAM-3-03 nonce 重放全链路：第二次提交 702722 → PROOF_INVALID")
    void nonceReplayEndToEnd() throws Exception {
        stubActiveDevice();
        String nonce = "nonce-endtoend-00002";

        assertTrue(controller.verify(request(nonce)).isValid());
        DeviceProofVerifyResultVo replay = controller.verify(request(nonce));

        assertFalse(replay.isValid());
        assertEquals(DeviceProofReasonCode.PROOF_INVALID.name(), replay.getReasonCode());
    }

    @Test
    @DisplayName("TC-VIAM-3-07 阻断后再次校验返回主体不可用（状态变化立即体现）")
    void blockedAfterFirstVerification() throws Exception {
        stubActiveDevice();
        assertTrue(controller.verify(request("nonce-endtoend-00003")).isValid());

        when(principalRepository.findByHsmUid(UID)).thenReturn(Optional.of(SecurityPrincipal.builder()
                .principalId(PRINCIPAL_ID).hsmUid(UID).state(SecurityPrincipal.PrincipalState.BLOCKED).build()));

        DeviceProofVerifyResultVo blocked = controller.verify(request("nonce-endtoend-00004"));
        assertFalse(blocked.isValid());
        assertEquals(DeviceProofReasonCode.SUBJECT_UNAVAILABLE.name(), blocked.getReasonCode());
    }

    @Test
    @DisplayName("TC-VIAM-3-05 重复调用不写设备状态、不签发凭据（只落审计与 nonce 键）")
    void readOnlyIdempotent() throws Exception {
        stubActiveDevice();

        controller.verify(request("nonce-endtoend-00005"));
        controller.verify(request("nonce-endtoend-00006"));

        org.mockito.Mockito.verify(principalRepository, org.mockito.Mockito.never()).save(any());
        org.mockito.Mockito.verify(mappingRepository, org.mockito.Mockito.never()).save(any());
        org.mockito.Mockito.verify(enrollmentRepository, org.mockito.Mockito.never()).insert(any());
        org.mockito.Mockito.verify(enrollmentRepository, org.mockito.Mockito.never()).update(any());
        // 只落两条审计（每次校验一条），不产生其它写入
        verify(auditRepository, org.mockito.Mockito.times(2)).save(any());
    }
}
