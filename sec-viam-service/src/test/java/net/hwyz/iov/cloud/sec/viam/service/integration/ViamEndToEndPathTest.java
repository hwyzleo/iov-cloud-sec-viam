package net.hwyz.iov.cloud.sec.viam.service.integration;

import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnlineEvidenceVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionDecision;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BusinessKeyProvisioningAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceAdmissionAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.SecurityPrincipalAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.SuccessfulDeviceLoginAppService;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SuccessfulDeviceLogin;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DecisionAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SuccessfulDeviceLoginRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertificateVerificationAdapter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * 端到端关键路径集成测试（SEC-VIAM-DSN-CR-001 / T08）
 * <p>
 * 接入(ALLOW) → 可信成功建链 → 登录记录/onboarding 推进 → Keyprov request → ACK → 状态投影。
 * 使用内存仓储替身 + Mockito 组合；<b>无真实 Broker/DB/设备环境，真实环境联调如实标注未测</b>，
 * 本测试仅验证业务编排闭环语义。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class ViamEndToEndPathTest {

    private static final String UID = "HSM-0001";
    private static final String VIN = "VIN0000000000001";
    private static final String SN = "SN-0001";

    @Mock
    private CertificateVerificationAdapter certificateVerificationAdapter;

    // 内存仓储替身
    private final InMemorySecurityPrincipalRepository principalRepo = new InMemorySecurityPrincipalRepository();
    private final InMemoryMappingRepository mappingRepo = new InMemoryMappingRepository();
    private final InMemoryOnboardingRepository onboardingRepo = new InMemoryOnboardingRepository();
    private final InMemoryDecisionAuditRepo auditRepo = new InMemoryDecisionAuditRepo();
    private final InMemoryLoginRepository loginRepo = new InMemoryLoginRepository();
    private final InMemoryBusinessKeyRepo businessKeyRepo = new InMemoryBusinessKeyRepo();
    private final InMemoryProvisioningBatchRepo batchRepo = new InMemoryProvisioningBatchRepo();
    @Mock
    private ViamOutboxWriter outboxWriter;

    private DeviceAdmissionAppService admissionAppService;
    private SuccessfulDeviceLoginAppService loginAppService;
    private BusinessKeyProvisioningAppService keyprovAppService;

    @BeforeEach
    void setUp() throws Exception {
        admissionAppService = new DeviceAdmissionAppService(
                principalRepo, mappingRepo, onboardingRepo, auditRepo, certificateVerificationAdapter);
        loginAppService = new SuccessfulDeviceLoginAppService(
                loginRepo, principalRepo, mappingRepo, onboardingRepo, auditRepo, outboxWriter,
                new ObjectMapper().findAndRegisterModules());
        keyprovAppService = new BusinessKeyProvisioningAppService(
                principalRepo, mappingRepo, onboardingRepo, businessKeyRepo, batchRepo);
    }

    @Test
    void endToEnd_loginKeyprovAckStateProjection() throws Exception {
        // 预置：安全主体 + 资产映射
        SecurityPrincipal principal = SecurityPrincipal.builder()
                .principalId("PR-001").hsmUid(UID)
                .state(SecurityPrincipal.PrincipalState.ACTIVE).build();
        principalRepo.save(principal);
        mappingRepo.save(PrincipalAssetMapping.builder()
                .principalId("PR-001").vin(VIN).deviceSn(SN).bindingVersion(1L)
                .state(PrincipalAssetMapping.MappingState.ACTIVE).build());
        // 预置安全开通状态（PRE_ACTIVE 可准入；登录后应迁移至 ACTIVATING）
        onboardingRepo.save(DeviceOnboarding.builder()
                .principalId("PR-001").hsmUid(UID).vin(VIN).deviceSn(SN)
                .state(DeviceOnboarding.OnboardingState.PRE_ACTIVE).build());

        // PKI 验证成功
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
        // onboarding 进入 ACTIVATING
        DeviceOnboarding onboarding = onboardingRepo.findByPrincipalId("PR-001").orElseThrow();
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVATING, onboarding.getState());
        assertNotNull(onboarding.getFirstLoginTime());

        // 3. Keyprov request（canonical KeyProvisioningRequest bytes 由 protobuf 构造）
        net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest protoRequest =
                net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest.newBuilder()
                        .setRequestId("REQ-001")
                        .setIdempotencyKey("IK-001")
                        .setBusinessDomain("V2C_COMM")
                        .addPurposes(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
                        .addPurposes(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
                        .build();
        byte[] requestBytes = protoRequest.toByteArray();
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext ctx =
                net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext.builder()
                        .deviceSn(SN).hsmUid(UID).connectionGeneration(1).build();
        // 注入批次请求入口（经 keyprovAppService）
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse resp =
                keyprovAppService.request(ctx, requestBytes,
                        net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.sha256Hex(
                                new String(requestBytes, java.nio.charset.StandardCharsets.UTF_8)));
        assertNotNull(resp);
        assertEquals("REQ-001", resp.getRequestId());
        ProvisioningBatch batch = batchRepo.findByRequestId("REQ-001").orElseThrow();
        assertEquals(ProvisioningBatch.BatchState.PREPARING, batch.getStatus());

        // 4. Keyprov ACK（完整用途集）
        net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck protoAck =
                net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck.newBuilder()
                        .setRequestId("REQ-001")
                        .addItems(net.hwyz.iov.security.keyprov.v1.KeyImportItemResult.newBuilder()
                                .setPurpose(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
                                .setResult(net.hwyz.iov.security.keyprov.v1.KeyImportResult.KEY_IMPORT_RESULT_IMPORTED).build())
                        .addItems(net.hwyz.iov.security.keyprov.v1.KeyImportItemResult.newBuilder()
                                .setPurpose(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
                                .setResult(net.hwyz.iov.security.keyprov.v1.KeyImportResult.KEY_IMPORT_RESULT_IMPORTED).build())
                        .build();
        byte[] ackBytes = protoAck.toByteArray();
        // ACK 需先冻结 F（KL1）
        batch.freezeFirstIssuance(new byte[]{1}, "digest", 300);
        batchRepo.save(batch);
        net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult ackResult =
                keyprovAppService.ack(ctx, ackBytes,
                        net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.sha256Hex(
                                new String(ackBytes, java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome.SUCCESS,
                ackResult.getOutcome());

        // 5. 状态投影：onboarding 已 ACTIVE
        DeviceOnboarding activated = onboardingRepo.findByPrincipalId("PR-001").orElseThrow();
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVE, activated.getState());
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

        @Override
        public Optional<DeviceBusinessKey> findByKeyId(String keyId) {
            return Optional.ofNullable(byKeyId.get(keyId));
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
            if (key.getKeyId() != null) {
                byKeyId.put(key.getKeyId(), key);
            }
            if (key.getKeyState() == DeviceBusinessKey.KeyState.ACTIVE) {
                byCtx.put(key.getDeviceSn() + "|" + key.getBusinessDomain() + "|" + key.getPurpose(), key);
            }
            byReqPurp.put(key.getRequestId() + "|" + key.getPurpose(), key);
        }
    }

    static class InMemoryProvisioningBatchRepo implements ProvisioningBatchRepository {
        final Map<String, ProvisioningBatch> byReq = new HashMap<>();
        long nextId = 1;
        final Map<Long, List<net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem>> items = new HashMap<>();

        @Override
        public Optional<ProvisioningBatch> findByRequestId(String requestId) {
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
