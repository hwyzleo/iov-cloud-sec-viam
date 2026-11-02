package net.hwyz.iov.cloud.sec.viam.service.integration;

import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeDigestVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnlineEvidenceVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionDecision;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BusinessKeyProvisioningAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceAdmissionAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.SuccessfulDeviceLoginAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.BusinessKeyDerivedMaterialService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.BusinessKeyMaterialRouter;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.ImportProofVerifier;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyProvisioningResponseStore;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyprovEnvelopeAdapter;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.Kl1LeaseIssuanceService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.ParProtoWireCanonical;
import net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.ParProtoWireMapperV1;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.KeyProvisioningLease;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DecisionAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.KeyProvisioningLeaseRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SuccessfulDeviceLoginRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertificateVerificationAdapter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * 端到端关键路径集成测试（SEC-VIAM-DSN-CR-001 / T08 / G-2）
 * <p>
 * 接入(ALLOW) → 可信成功建链 → 登录记录/onboarding 推进 → Keyprov request（真实 canonical
 * bytes + KL1 租约）→ ACK（ImportProof 验签）→ 状态投影 → 幂等重放（Provider 调用增量=0）。
 * 使用内存仓储替身 + Mockito（Provider 为 contract-complete 测试替身，产生真实可验证
 * canonical envelope）；<b>无真实 KMS/Broker/DB/设备环境，真实环境联调如实标注未测</b>。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class ViamEndToEndPathTest {

    private static final String UID = "HSM-0001";
    private static final String VIN = "VHN00000000000001"; // 满足 KeyAnchor.vin [A-HJ-NPR-Z0-9] 且 17 位
    private static final String SN = "SN-0001";
    private static final String TEST_STORE_KEY =
            "dGVzdC1rZXktMzItYnl0ZXMtMDEyMzQ1Njc4OWFiY2Q="; // Base64 AES-256（32 字节）

    @Mock
    private CertificateVerificationAdapter certificateVerificationAdapter;
    @Mock
    private KeyProvisioningTemplate keyProvisioningTemplate;
    @Mock
    private DerivedEnvelopeDigestVerifier envelopeDigestVerifier;
    @Mock
    private net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier frameworkImportProofVerifier;
    @Mock
    private ViamOutboxWriter outboxWriter;

    // 内存仓储替身
    private final InMemorySecurityPrincipalRepository principalRepo = new InMemorySecurityPrincipalRepository();
    private final InMemoryMappingRepository mappingRepo = new InMemoryMappingRepository();
    private final InMemoryOnboardingRepository onboardingRepo = new InMemoryOnboardingRepository();
    private final InMemoryDecisionAuditRepo auditRepo = new InMemoryDecisionAuditRepo();
    private final InMemoryLoginRepository loginRepo = new InMemoryLoginRepository();
    private final InMemoryBusinessKeyRepo businessKeyRepo = new InMemoryBusinessKeyRepo();
    private final InMemoryProvisioningBatchRepo batchRepo = new InMemoryProvisioningBatchRepo();
    private final InMemoryCredentialRepo credentialRepo = new InMemoryCredentialRepo();
    private final InMemoryLeaseRepo leaseRepo = new InMemoryLeaseRepo();

    private DeviceAdmissionAppService admissionAppService;
    private SuccessfulDeviceLoginAppService loginAppService;
    private BusinessKeyProvisioningAppService keyprovAppService;
    private AtomicInteger providerCalls;

    @BeforeEach
    void setUp() throws Exception {
        admissionAppService = new DeviceAdmissionAppService(
                principalRepo, mappingRepo, onboardingRepo, auditRepo, certificateVerificationAdapter);
        loginAppService = new SuccessfulDeviceLoginAppService(
                loginRepo, principalRepo, mappingRepo, onboardingRepo, auditRepo, outboxWriter,
                new ObjectMapper().findAndRegisterModules());

        // Keyprov 业务链：真实 codec/冻结/租约 + contract-complete Provider 替身
        providerCalls = new AtomicInteger(0);
        when(keyProvisioningTemplate.deriveAndWrap(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenAnswer(inv -> {
                    providerCalls.incrementAndGet();
                    return fixtureDerivedKey(inv.getArgument(2));
                });
        ParProtoWireMapperV1 wireMapper = new ParProtoWireMapperV1(provider(() -> envelopeDigestVerifier));
        BusinessKeyMaterialRouter materialRouter = new BusinessKeyMaterialRouter(
                provider(() -> keyProvisioningTemplate), provider(() -> null));
        BusinessKeyDerivedMaterialService derivedMaterialService =
                new BusinessKeyDerivedMaterialService(businessKeyRepo);
        KeyprovEnvelopeAdapter envelopeAdapter = new KeyprovEnvelopeAdapter(wireMapper);
        KeyProvisioningResponseStore responseStore =
                new KeyProvisioningResponseStore(batchRepo, TEST_STORE_KEY, 1, "");
        Kl1LeaseIssuanceService leaseIssuanceService =
                new Kl1LeaseIssuanceService(responseStore, leaseRepo, batchRepo);
        lenient().when(frameworkImportProofVerifier.verify(any()))
                .thenAnswer(inv -> {
                    ImportProofVerificationRequest req = inv.getArgument(0);
                    return new VerifiedImportProof(ImportProofAlgorithm.ECDSA_P256_SHA256_P1363,
                            req.expectedCertificateDigest(), req.purpose(), req.envelopeDigest(), Instant.now());
                });
        ImportProofVerifier importProofVerifier =
                new ImportProofVerifier(provider(() -> frameworkImportProofVerifier));

        keyprovAppService = new BusinessKeyProvisioningAppService(
                principalRepo, mappingRepo, onboardingRepo, businessKeyRepo, batchRepo, credentialRepo,
                materialRouter, derivedMaterialService, envelopeAdapter, responseStore,
                leaseIssuanceService, importProofVerifier, outboxWriter,
                new ObjectMapper().findAndRegisterModules());
    }

    private static <T> ObjectProvider<T> provider(java.util.function.Supplier<T> supplier) {
        return new ObjectProvider<T>() {
            @Override
            public T getObject() {
                return supplier.get();
            }

            @Override
            public T getObject(Object... args) {
                return supplier.get();
            }

            @Override
            public T getIfAvailable() {
                return supplier.get();
            }

            @Override
            public T getIfUnique() {
                return supplier.get();
            }
        };
    }

    @Test
    void endToEnd_loginKeyprovAckStateProjection() throws Exception {
        // 预置：安全主体 + 资产映射 + 设备证书 + 开通状态
        SecurityPrincipal principal = SecurityPrincipal.builder()
                .principalId("PR-001").hsmUid(UID)
                .state(SecurityPrincipal.PrincipalState.ACTIVE).build();
        principalRepo.save(principal);
        mappingRepo.save(PrincipalAssetMapping.builder()
                .principalId("PR-001").vin(VIN).deviceSn(SN).bindingVersion(1L)
                .state(PrincipalAssetMapping.MappingState.ACTIVE).build());
        onboardingRepo.save(DeviceOnboarding.builder()
                .principalId("PR-001").hsmUid(UID).vin(VIN).deviceSn(SN)
                .state(DeviceOnboarding.OnboardingState.PRE_ACTIVE).build());
        credentialRepo.save(CredentialEnrollment.builder()
                .requestId("CERT-1").pkiRequestId("PKI-1").certSn("0a1b2c")
                .deviceSn(SN).hsmUid(UID).certificateFingerprint("fp")
                .leafCertificateDigest(new byte[32])
                .certStatus(CredentialEnrollment.CertificateState.ACTIVE).build());

        when(certificateVerificationAdapter.verify(anyString(), anyString(), anyString(), any()))
                .thenReturn(new CertificateVerificationAdapter.CertificateVerificationResult(
                        CertificateStatus.VALID, UID, null, Instant.parse("2027-01-01T00:00:00Z"), Instant.now()));

        // 1. 准入 ALLOW（含不可变准入快照）
        DeviceAdmissionResultVo admission = admissionAppService.decide(
                DeviceAdmissionCheckVo.builder().uid(UID).certSerial("0a1b2c").certFingerprint("fp")
                        .leafCertificateDer("AQID").ts(Instant.now()).build(), "VAGW");
        assertEquals(AdmissionDecision.ALLOW, admission.getDecision());
        assertNotNull(admission.getAdmissionDecisionId());

        // 2. 可信成功建链（携带准入证据）
        String decisionId = admission.getAdmissionDecisionId();
        DecisionAudit audit = auditRepo.findByAdmissionDecisionId(decisionId).orElseThrow();
        DeviceOnlineEvidenceVo evidence = DeviceOnlineEvidenceVo.builder()
                .eventId("EV-001").eventType("DEVICE_ONLINE")
                .hsmUid(UID).vin(VIN).sessionId("S1").connectionGeneration(1)
                .certSerial("0a1b2c").occurredAt(Instant.now()).timeSource("EMQX")
                .admissionDecisionId(decisionId)
                .admissionSnapshotDigest(audit.getSnapshotDigest())
                .admissionSnapshotExpiresAt(audit.getSnapshotExpiresAt())
                .admissionVin(VIN)
                .build();
        String result = loginAppService.handleDeviceOnline(evidence, "vagw.device.online");
        assertEquals("LOGIN_RECORDED_MIGRATED", result);
        DeviceOnboarding onboarding = onboardingRepo.findByPrincipalId("PR-001").orElseThrow();
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVATING, onboarding.getState());

        // 3. Keyprov request（V2C 完整用途集；Provider 调用 1 次）
        KeyProvisioningRequest protoRequest = KeyProvisioningRequest.newBuilder()
                .setRequestId("REQ-001")
                .setIdempotencyKey("IK-001")
                .setBusinessDomain("V2C_COMM")
                .addSupportedEnvelopeFormats(
                        net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
                .addSupportedWrappingSuites(
                        net.hwyz.iov.security.keyprov.v1.WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
                .addPurposes(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
                .addPurposes(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
                .build();
        byte[] requestBytes = protoRequest.toByteArray();
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext ctx =
                net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext.builder()
                        .deviceSn(SN).hsmUid(UID).connectionGeneration(1).build();

        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse resp =
                keyprovAppService.request(ctx, requestBytes, ViamUtils.sha256Hex(requestBytes));
        assertNotNull(resp);
        assertEquals("REQ-001", resp.getRequestId());
        assertEquals(net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome.SUCCESS,
                resp.getOutcome());
        assertNotNull(resp.getMessageId());
        assertTrue(resp.getPayloadBytes() != null && resp.getPayloadBytes().length > 0);
        // 真实 canonical bytes：可解析且 field4 = expire_at_ms 存在
        KeyProvisioningResponse parsed = KeyProvisioningResponse.parseFrom(resp.getPayloadBytes());
        assertEquals("REQ-001", parsed.getRequestId());
        assertEquals(2, parsed.getItemsCount());
        assertTrue(parsed.getExpireAtMs() > 0);
        ProvisioningBatch batch = batchRepo.findByRequestId("REQ-001").orElseThrow();
        assertEquals(ProvisioningBatch.BatchState.WAIT_DEVICE_ACK, batch.getStatus());
        assertNotNull(batch.getAckDeadlineAt());
        assertEquals(2, providerCalls.get());
        // KL1 租约已签发
        assertNotNull(leaseRepo.findByMessageId(resp.getMessageId()).orElseThrow());

        // 3b. 同 requestId 幂等重放：续租（新 messageId），Provider 调用增量 = 0
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse replay =
                keyprovAppService.request(ctx, requestBytes, ViamUtils.sha256Hex(requestBytes));
        assertNotNull(replay.getMessageId());
        assertEquals("REQ-001", replay.getRequestId());
        assertEquals(2, providerCalls.get()); // 重放不调用 Provider

        // 4. Keyprov ACK（完整用途集 + ImportProof 验签）
        KeyProvisioningAck protoAck = KeyProvisioningAck.newBuilder()
                .setRequestId("REQ-001")
                .addItems(KeyImportItemResult.newBuilder()
                        .setPurpose(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
                        .setKeyId("LK-UPLINK_AEAD")
                        .setBusinessKeyVersion(1)
                        .setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
                        .setImportProof(com.google.protobuf.ByteString.copyFrom(new byte[]{1, 2, 3, 4})).build())
                .addItems(KeyImportItemResult.newBuilder()
                        .setPurpose(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
                        .setKeyId("LK-DOWNLINK_AEAD")
                        .setBusinessKeyVersion(1)
                        .setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
                        .setImportProof(com.google.protobuf.ByteString.copyFrom(new byte[]{1, 2, 3, 4})).build())
                .build();
        byte[] ackBytes = protoAck.toByteArray();
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult ackResult =
                keyprovAppService.ack(ctx, ackBytes, ViamUtils.sha256Hex(ackBytes));
        assertEquals(net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome.SUCCESS,
                ackResult.getOutcome());
        assertEquals("REQ-001", ackResult.getRequestId());
        assertTrue(ackResult.getPayloadBytes().length > 0);

        // 5. 状态投影：onboarding 已 ACTIVE；批次 COMPLETED
        DeviceOnboarding activated = onboardingRepo.findByPrincipalId("PR-001").orElseThrow();
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVE, activated.getState());
        ProvisioningBatch completed = batchRepo.findByRequestId("REQ-001").orElseThrow();
        assertEquals(ProvisioningBatch.BatchState.COMPLETED, completed.getStatus());

        // 6. ACTIVE 一致重复 ACK：幂等成功，不重复激活/不发事件
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult dupAck =
                keyprovAppService.ack(ctx, ackBytes, ViamUtils.sha256Hex(ackBytes));
        assertEquals(net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome.SUCCESS,
                dupAck.getOutcome());
        assertEquals(2, providerCalls.get()); // 重复 ACK 不调用 Provider
    }

    /**
     * contract-complete Provider 替身：生成真实可验证 canonical envelope（view 字段一致、
     * aad_digest=SHA-256(canonical_aad)）。
     */
    private DerivedWrappedKey fixtureDerivedKey(Object purposeArg) {
        KeyPurpose purpose = (KeyPurpose) purposeArg;
        String logicalKeyId = "LK-" + purpose.name();
        String operationId = "OP-" + logicalKeyId;
        byte[] recipientCertDigest = ParProtoWireCanonical.sha256("0a1b2c".getBytes(StandardCharsets.UTF_8));
        byte[] canonicalAad = ParProtoWireCanonical.canonicalAad(
                1, 2, purpose == KeyPurpose.UPLINK_AEAD ? 1 : 2, 1L, 100L, recipientCertDigest,
                "REQ-001", "V2C_COMM", logicalKeyId, "v1");
        byte[] aadDigest = ParProtoWireCanonical.aadDigest(canonicalAad);
        byte[] envelopeDigest = ParProtoWireCanonical.sha256(
                ("env-" + logicalKeyId).getBytes(StandardCharsets.UTF_8));
        byte[] kcv = new byte[3]; // KEY_CHECK_VALUE_LENGTH=3
        new java.security.SecureRandom().nextBytes(kcv);
        byte[] serverEphemeral = new byte[65];
        serverEphemeral[0] = 0x04; // P-256 SEC1 uncompressed 点前缀
        EcdhEsP256EnvelopeViewV1 view = new EcdhEsP256EnvelopeViewV1(
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1,
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                serverEphemeral, new byte[32], "v1", new byte[12],
                new byte[]{9, 8, 7, 6, 5}, new byte[16], canonicalAad, aadDigest,
                recipientCertDigest, logicalKeyId, purpose, 1L, 100L, "v1", operationId,
                envelopeDigest, kcv, ParProtoWireCanonical.AAD_PROFILE);
        return new DerivedWrappedKey(logicalKeyId, "kms-ref-" + logicalKeyId, 100L, "v1",
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, view, envelopeDigest,
                envelopeDigest, kcv, operationId);
    }

    // ================= 内存仓储替身 =================

    static class InMemorySecurityPrincipalRepository implements SecurityPrincipalRepository {
        final Map<String, SecurityPrincipal> byId = new HashMap<>();
        final Map<String, SecurityPrincipal> byUid = new HashMap<>();

        @Override
        public Optional<SecurityPrincipal> findByPrincipalId(String principalId) {
            return Optional.ofNullable(byId.get(principalId));
        }

        @Override
        public Optional<SecurityPrincipal> findByHsmUid(String hsmUid) {
            return Optional.ofNullable(byUid.get(hsmUid));
        }

        @Override
        public void save(SecurityPrincipal principal) {
            byId.put(principal.getPrincipalId(), principal);
            byUid.put(principal.getHsmUid(), principal);
        }

        @Override
        public List<SecurityPrincipal> listAll(int offset, int limit) {
            return new ArrayList<>(byId.values());
        }
    }

    static class InMemoryMappingRepository implements PrincipalAssetMappingRepository {
        final List<PrincipalAssetMapping> mappings = new ArrayList<>();

        @Override
        public Optional<PrincipalAssetMapping> findByPrincipalAndVin(String principalId, String vin) {
            return mappings.stream().filter(m -> m.getPrincipalId().equals(principalId) && m.getVin().equals(vin)
                    && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).findFirst();
        }

        @Override
        public List<PrincipalAssetMapping> listActiveByPrincipalId(String principalId) {
            return mappings.stream().filter(m -> m.getPrincipalId().equals(principalId)
                    && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).toList();
        }

        @Override
        public List<PrincipalAssetMapping> listActiveByVin(String vin) {
            return mappings.stream().filter(m -> m.getVin().equals(vin)
                    && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).toList();
        }

        @Override
        public Optional<PrincipalAssetMapping> findActiveByDeviceSn(String deviceSn) {
            return mappings.stream().filter(m -> m.getDeviceSn().equals(deviceSn)
                    && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).findFirst();
        }

        @Override
        public void save(PrincipalAssetMapping mapping) {
            mappings.removeIf(m -> m.getDeviceSn().equals(mapping.getDeviceSn()));
            mappings.add(mapping);
        }
    }

    static class InMemoryOnboardingRepository implements DeviceOnboardingRepository {
        final Map<String, DeviceOnboarding> byId = new HashMap<>();

        @Override
        public Optional<DeviceOnboarding> findByPrincipalId(String principalId) {
            return Optional.ofNullable(byId.get(principalId));
        }

        @Override
        public void save(DeviceOnboarding onboarding) {
            byId.put(onboarding.getPrincipalId(), onboarding);
        }
    }

    static class InMemoryDecisionAuditRepo implements DecisionAuditRepository {
        final Map<String, DecisionAudit> audits = new HashMap<>();

        @Override
        public Optional<DecisionAudit> findByAdmissionDecisionId(String admissionDecisionId) {
            return Optional.ofNullable(audits.get(admissionDecisionId));
        }

        @Override
        public void save(DecisionAudit audit) {
            audits.put(audit.getAdmissionDecisionId(), audit);
        }
    }

    static class InMemoryLoginRepository implements SuccessfulDeviceLoginRepository {
        final Map<String, SuccessfulDeviceLogin> byId = new HashMap<>();
        final Map<String, Instant> first = new HashMap<>();
        final Map<String, Instant> last = new HashMap<>();

        @Override
        public Optional<SuccessfulDeviceLogin> findByLoginId(String loginId) {
            return Optional.ofNullable(byId.get(loginId));
        }

        @Override
        public void save(SuccessfulDeviceLogin login) {
            byId.put(login.getLoginId(), login);
            first.merge(login.getPrincipalId(), login.getOccurredAt(),
                    (a, b) -> a.isBefore(b) ? a : b);
            last.merge(login.getPrincipalId(), login.getOccurredAt(),
                    (a, b) -> a.isAfter(b) ? a : b);
        }

        @Override
        public Optional<Instant> findFirstLoginTime(String principalId) {
            return Optional.ofNullable(first.get(principalId));
        }

        @Override
        public Optional<Instant> findLastLoginTime(String principalId) {
            return Optional.ofNullable(last.get(principalId));
        }
    }

    static class InMemoryBusinessKeyRepo implements DeviceBusinessKeyRepository {
        final Map<String, DeviceBusinessKey> byKeyId = new HashMap<>();
        final Map<String, DeviceBusinessKey> byCtx = new HashMap<>();
        final Map<String, DeviceBusinessKey> byReqPurp = new HashMap<>();
        final Map<Long, DeviceBusinessKey> byId = new HashMap<>();
        long nextId = 1;

        @Override
        public Optional<DeviceBusinessKey> findByKeyId(String keyId) {
            return Optional.ofNullable(byKeyId.get(keyId));
        }

        @Override
        public Optional<DeviceBusinessKey> findByKeyIdForUpdate(String keyId) {
            return Optional.ofNullable(byKeyId.get(keyId));
        }

        @Override
        public Optional<DeviceBusinessKey> findById(Long id) {
            return Optional.ofNullable(byId.get(id));
        }

        @Override
        public Optional<DeviceBusinessKey> findActiveByContext(String deviceSn, String businessDomain, String purpose) {
            return Optional.ofNullable(byCtx.get(deviceSn + "|" + businessDomain + "|" + purpose));
        }

        @Override
        public Optional<DeviceBusinessKey> findByRequestIdAndPurpose(String requestId, String purpose) {
            return Optional.ofNullable(byReqPurp.get(requestId + "|" + purpose));
        }

        @Override
        public void save(DeviceBusinessKey key) {
            if (key.getId() == null) {
                key.setId(nextId++);
            }
            if (key.getKeyId() != null) {
                byKeyId.put(key.getKeyId(), key);
            }
            if (key.getKeyState() == DeviceBusinessKey.KeyState.ACTIVE) {
                byCtx.put(key.getDeviceSn() + "|" + key.getBusinessDomain() + "|" + key.getPurpose(), key);
            }
            byReqPurp.put(key.getRequestId() + "|" + key.getPurpose(), key);
            byId.put(key.getId(), key);
        }
    }

    static class InMemoryCredentialRepo implements CredentialEnrollmentRepository {
        final List<CredentialEnrollment> enrollments = new ArrayList<>();

        @Override
        public Optional<CredentialEnrollment> findByRequestId(String requestId) {
            return enrollments.stream().filter(e -> requestId.equals(e.getRequestId())).findFirst();
        }

        @Override
        public Optional<CredentialEnrollment> findByCertSn(String certSn) {
            return enrollments.stream().filter(e -> certSn.equals(e.getCertSn())).findFirst();
        }

        @Override
        public Optional<CredentialEnrollment> findByVinAndUidAndSpkiAndProfile(
                String vin, String hsmUid, String publicKeySha256, String profile) {
            return Optional.empty();
        }

        @Override
        public Optional<CredentialEnrollment> findKeyConflictByVinAndUidAndProfile(
                String vin, String hsmUid, String publicKeySha256, String profile) {
            return Optional.empty();
        }

        @Override
        public Optional<CredentialEnrollment> findActiveByVinAndDeviceCategory(String vin, String deviceCategory) {
            return enrollments.stream().filter(e -> vin.equals(e.getVin())
                    && e.getCertStatus() == CredentialEnrollment.CertificateState.ACTIVE).findFirst();
        }

        @Override
        public List<CredentialEnrollment> listByDeviceSn(String deviceSn) {
            return enrollments.stream().filter(e -> deviceSn.equals(e.getDeviceSn())).toList();
        }

        @Override
        public List<CredentialEnrollment> listUpdatedAfter(Instant updatedAfter, int limit) {
            return List.of();
        }

        @Override
        public void insert(CredentialEnrollment enrollment) {
            enrollments.add(enrollment);
        }

        @Override
        public void update(CredentialEnrollment enrollment) {
            enrollments.removeIf(e -> e.getRequestId().equals(enrollment.getRequestId()));
            enrollments.add(enrollment);
        }

        @Override
        public void supersedeActiveByDeviceSnAndProfile(String deviceSn, String profile, String excludeRequestId) {
            // 内存替身：忽略
        }

        void save(CredentialEnrollment enrollment) {
            enrollments.removeIf(e -> e.getRequestId().equals(enrollment.getRequestId()));
            enrollments.add(enrollment);
        }
    }

    static class InMemoryLeaseRepo implements KeyProvisioningLeaseRepository {
        final Map<String, KeyProvisioningLease> byMessageId = new HashMap<>();
        final Map<String, KeyProvisioningLease> byProvSeq = new HashMap<>();

        @Override
        public Optional<KeyProvisioningLease> findByProvisioningAndSeq(Long provisioningId, int leaseSeq) {
            return Optional.ofNullable(byProvSeq.get(provisioningId + "|" + leaseSeq));
        }

        @Override
        public Optional<KeyProvisioningLease> findByMessageId(String messageId) {
            return Optional.ofNullable(byMessageId.get(messageId));
        }

        @Override
        public void save(KeyProvisioningLease lease) {
            byMessageId.put(lease.getMessageId(), lease);
            byProvSeq.put(lease.getProvisioningId() + "|" + lease.getLeaseSeq(), lease);
        }
    }

    static class InMemoryProvisioningBatchRepo implements ProvisioningBatchRepository {
        final Map<String, ProvisioningBatch> byReq = new HashMap<>();
        long nextId = 1;
        final Map<Long, List<net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem>> items =
                new HashMap<>();

        @Override
        public Optional<ProvisioningBatch> findByRequestId(String requestId) {
            return Optional.ofNullable(byReq.get(requestId));
        }

        @Override
        public Optional<ProvisioningBatch> findByRequestIdForUpdate(String requestId) {
            return Optional.ofNullable(byReq.get(requestId));
        }

        @Override
        public void save(ProvisioningBatch batch) {
            if (batch.getId() == null) {
                batch.setId(nextId++);
            }
            byReq.put(batch.getRequestId(), batch);
        }

        @Override
        public void saveItem(net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem item) {
            List<net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem> list =
                    items.computeIfAbsent(item.getProvisioningId(), k -> new ArrayList<>());
            list.removeIf(i -> i.getPurpose().equals(item.getPurpose()));
            list.add(item);
        }

        @Override
        public List<net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem> listItemsByProvisioningId(Long provisioningId) {
            return new ArrayList<>(items.getOrDefault(provisioningId, List.of()));
        }
    }
}
