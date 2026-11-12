package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningBatchVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningDiagnosisVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningResolveVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.KeyProvisioningLease;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificatePage;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificateQuery;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.KeyProvisioningLeaseRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务密钥治理只读查询测试（SEC-VIAM-DSN-CR-002 / T15 / D-VIAM-017 / D-VIAM-018）。
 * <p>
 * 覆盖：批次治理视图、目录行阻塞与批次阻塞分层、诊断脱敏与证据、
 * 证书申请→开通批次桥接的 UNIQUE / MULTIPLE / NONE 三种解析结果。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("SEC-VIAM-DSN-CR-002 业务密钥治理查询")
class BusinessKeyGovernanceQueryAppServiceTest {

    private InMemBatchRepo batchRepo;
    private InMemBusinessKeyRepo keyRepo;
    private InMemLeaseRepo leaseRepo;
    private InMemEnrollmentRepo enrollmentRepo;
    private BusinessKeyGovernanceQueryAppService service;

    @BeforeEach
    void setUp() {
        batchRepo = new InMemBatchRepo();
        keyRepo = new InMemBusinessKeyRepo();
        leaseRepo = new InMemLeaseRepo();
        enrollmentRepo = new InMemEnrollmentRepo();
        service = new BusinessKeyGovernanceQueryAppService(batchRepo, keyRepo, leaseRepo, enrollmentRepo);
    }

    @Test
    @DisplayName("T15 批次视图：返回用途明细、目录行状态与最近租约")
    void batchReturnsItemsDirectoryStateAndLease() {
        ProvisioningBatch batch = batch("kp-1", ProvisioningBatch.BatchState.WAIT_DEVICE_ACK);
        batchRepo.save(batch);
        batchRepo.items.add(item(batch.getId(), "UPLINK_AEAD", "KEY-1"));
        keyRepo.keys.add(key("KEY-1", DeviceBusinessKey.KeyState.ACTIVE, 3L));
        leaseRepo.leases.add(lease(batch.getId(), 2));

        ProvisioningBatchVo vo = service.batch("kp-1");

        assertEquals("kp-1", vo.getRequestId());
        assertEquals("WAIT_DEVICE_ACK", vo.getStatus());
        assertEquals(1, vo.getItems().size());
        assertEquals("ACTIVE", vo.getItems().get(0).getDirectoryKeyState());
        assertEquals(3L, vo.getItems().get(0).getDirectoryBusinessKeyVersion());
        assertNotNull(vo.getLease());
        assertEquals(2, vo.getLease().getLeaseSeq());
        assertEquals("NONE", vo.getBlockingLevel());
    }

    @Test
    @DisplayName("T15 批次不存在返回 702403")
    void batchRejectsUnknownRequestId() {
        ViamServiceException ex = assertThrows(ViamServiceException.class, () -> service.batch("kp-none"));
        assertEquals(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T15 批次阻塞：RECONCILE_REQUIRED 判定为 BATCH 且不可清理")
    void diagnosisMarksBatchLevelBlocking() {
        ProvisioningBatch batch = batch("kp-2", ProvisioningBatch.BatchState.RECONCILE_REQUIRED);
        batch.setFailReason("PROVIDER_UNKNOWN");
        batchRepo.save(batch);

        ProvisioningDiagnosisVo vo = service.diagnosis("kp-2");

        assertEquals("BATCH", vo.getBlockingLevel());
        assertTrue(vo.getBlockingReason().contains("PROVIDER_UNKNOWN"));
        assertEquals(Boolean.TRUE, vo.getClearable());
        assertTrue(vo.getEvidence().stream().anyMatch(e -> e.contains("批次状态=RECONCILE_REQUIRED")));
    }

    @Test
    @DisplayName("T15 目录行阻塞：批次仍推进但目录行 RECONCILE_REQUIRED 判定为 LOCAL_DIRECTORY")
    void diagnosisMarksDirectoryLevelBlocking() {
        ProvisioningBatch batch = batch("kp-3", ProvisioningBatch.BatchState.WAIT_DEVICE_ACK);
        batchRepo.save(batch);
        batchRepo.items.add(item(batch.getId(), "DOWNLINK_AEAD", "KEY-2"));
        keyRepo.keys.add(key("KEY-2", DeviceBusinessKey.KeyState.PENDING_RECOVERY, 4L));

        ProvisioningDiagnosisVo vo = service.diagnosis("kp-3");

        assertEquals("LOCAL_DIRECTORY", vo.getBlockingLevel());
        assertTrue(vo.getBlockingReason().contains("DOWNLINK_AEAD"));
        // 批次状态本身不是可清理的批次阻塞态
        assertEquals(Boolean.FALSE, vo.getClearable());
    }

    @Test
    @DisplayName("T15 终态批次：EXPIRED 判定为不可清阻断且标注不复活")
    void diagnosisMarksExpiredBatchFrozen() {
        ProvisioningBatch batch = batch("kp-4", ProvisioningBatch.BatchState.EXPIRED);
        batch.setTerminalReason("ACK_TIMEOUT");
        batchRepo.save(batch);

        ProvisioningDiagnosisVo vo = service.diagnosis("kp-4");

        assertEquals("BATCH", vo.getBlockingLevel());
        assertTrue(vo.getBlockingReason().contains("终态"));
        assertEquals(Boolean.FALSE, vo.getClearable());
    }

    @Test
    @DisplayName("T15 存量未迁移批次：KL1 缺失时不推断，诊断标注明确")
    void diagnosisDoesNotInferOnLegacyBatch() {
        ProvisioningBatch batch = batch("kp-5", ProvisioningBatch.BatchState.WAIT_DEVICE_ACK);
        batch.setLifecycleProfile(null);
        batchRepo.save(batch);

        ProvisioningDiagnosisVo vo = service.diagnosis("kp-5");

        assertNull(vo.getLifecycleProfile());
        assertTrue(vo.getEvidence().stream().anyMatch(e -> e.contains("KL1标识缺失")));
    }

    @Test
    @DisplayName("T15 桥接：未终结批次唯一时返回 UNIQUE 并给出 selected")
    void resolveReturnsUniqueOpenBatch() {
        enrollmentRepo.enrollments.add(enrollment("MPT-CERT-1", "SN-1", "VIN1"));
        ProvisioningBatch open = batch("kp-10", ProvisioningBatch.BatchState.WAIT_DEVICE_ACK);
        batchRepo.save(open);

        ProvisioningResolveVo vo = service.resolveByCertificateRequest("MPT-CERT-1", null, false);

        assertEquals("UNIQUE", vo.getResolution());
        assertEquals("kp-10", vo.getSelected());
        assertEquals("SN-1", vo.getDeviceSn());
        assertEquals("V2C_COMM", vo.getBusinessDomain());
    }

    @Test
    @DisplayName("T15 桥接：多个未终结批次时不静默择一（MULTIPLE 且 selected 为空）")
    void resolveReturnsMultipleCandidatesWithoutPickingOne() {
        enrollmentRepo.enrollments.add(enrollment("MPT-CERT-2", "SN-1", "VIN1"));
        batchRepo.save(batch("kp-11", ProvisioningBatch.BatchState.WAIT_DEVICE_ACK));
        batchRepo.save(batch("kp-12", ProvisioningBatch.BatchState.RECONCILE_REQUIRED));

        ProvisioningResolveVo vo = service.resolveByCertificateRequest("MPT-CERT-2", "V2C_COMM", true);

        assertEquals("MULTIPLE", vo.getResolution());
        assertNull(vo.getSelected());
        assertEquals(2, vo.getCandidates().size());
    }

    @Test
    @DisplayName("T15 桥接：无候选时返回 NONE")
    void resolveReturnsNoneWhenNoCandidate() {
        enrollmentRepo.enrollments.add(enrollment("MPT-CERT-3", "SN-9", "VIN9"));

        ProvisioningResolveVo vo = service.resolveByCertificateRequest("MPT-CERT-3", null, true);

        assertEquals("NONE", vo.getResolution());
        assertTrue(vo.getCandidates().isEmpty());
    }

    @Test
    @DisplayName("T15 桥接：证书申请不存在返回 702213")
    void resolveRejectsUnknownCertificateRequest() {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.resolveByCertificateRequest("NOPE", null, false));
        assertEquals(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST.getCode(), ex.getCode());
    }

    // ================= 夹具 =================

    private static ProvisioningBatch batch(String requestId, ProvisioningBatch.BatchState state) {
        return ProvisioningBatch.builder()
                .requestId(requestId).deviceSn("SN-1").businessDomain("V2C_COMM").status(state)
                .lifecycleProfile("KEYPROV-LIFECYCLE-1").leaseSeq(2)
                .startedAt(Instant.now().minusSeconds(60)).build();
    }

    private static ProvisioningItem item(Long provisioningId, String purpose, String keyId) {
        return ProvisioningItem.builder()
                .provisioningId(provisioningId).purpose(purpose).keyId(keyId)
                .businessKeyVersion(3L).envelopeFormat("ECDH_ES_P256_V1")
                .deviceResult(ProvisioningItem.DeviceResult.PENDING).build();
    }

    private static DeviceBusinessKey key(String keyId, DeviceBusinessKey.KeyState state, long version) {
        return DeviceBusinessKey.builder()
                .keyId(keyId).deviceSn("SN-1").businessDomain("V2C_COMM").purpose("UPLINK_AEAD")
                .businessKeyVersion(version).keyState(state).build();
    }

    private static KeyProvisioningLease lease(Long provisioningId, int seq) {
        return KeyProvisioningLease.builder()
                .provisioningId(provisioningId).leaseSeq(seq)
                .issuedAt(Instant.now().minusSeconds(30)).expireAt(Instant.now().plusSeconds(30))
                .messageId("MSG-" + seq).build();
    }

    private static CredentialEnrollment enrollment(String requestId, String deviceSn, String vin) {
        return CredentialEnrollment.builder()
                .requestId(requestId).deviceSn(deviceSn).vin(vin)
                .certificateProfile("TBOX_TSP_CLIENT")
                .certStatus(CredentialEnrollment.CertificateState.ACTIVE).build();
    }

    // ================= 内存替身 =================

    static class InMemBatchRepo implements ProvisioningBatchRepository {
        final List<ProvisioningBatch> batches = new ArrayList<>();
        final List<ProvisioningItem> items = new ArrayList<>();
        long nextId = 1;

        @Override
        public Optional<ProvisioningBatch> findByRequestId(String requestId) {
            return batches.stream().filter(b -> requestId.equals(b.getRequestId())).findFirst();
        }

        @Override
        public Optional<ProvisioningBatch> findOpenByDeviceSnAndDomain(String deviceSn, String businessDomain) {
            return batches.stream()
                    .filter(b -> deviceSn.equals(b.getDeviceSn()) && businessDomain.equals(b.getBusinessDomain()))
                    .findFirst();
        }

        @Override
        public List<ProvisioningBatch> listByDeviceSnAndDomain(String deviceSn, String businessDomain,
                                                               boolean includeTerminal, int limit) {
            return batches.stream()
                    .filter(b -> deviceSn.equals(b.getDeviceSn()) && businessDomain.equals(b.getBusinessDomain()))
                    .limit(limit)
                    .toList();
        }

        @Override
        public Optional<ProvisioningBatch> findByRequestIdForUpdate(String requestId) {
            return findByRequestId(requestId);
        }

        @Override
        public void save(ProvisioningBatch batch) {
            if (batch.getId() == null) {
                batch.setId(nextId++);
            }
            batches.removeIf(b -> b.getRequestId().equals(batch.getRequestId()));
            batches.add(batch);
        }

        @Override
        public void saveItem(ProvisioningItem item) {
            items.add(item);
        }

        @Override
        public List<ProvisioningItem> listItemsByProvisioningId(Long provisioningId) {
            return items.stream().filter(i -> provisioningId != null
                    && provisioningId.equals(i.getProvisioningId())).toList();
        }
    }

    static class InMemBusinessKeyRepo implements DeviceBusinessKeyRepository {
        final List<DeviceBusinessKey> keys = new ArrayList<>();

        @Override
        public Optional<DeviceBusinessKey> findByKeyId(String keyId) {
            return keys.stream().filter(k -> keyId != null && keyId.equals(k.getKeyId())).findFirst();
        }

        @Override
        public Optional<DeviceBusinessKey> findActiveByContext(String deviceSn, String businessDomain,
                                                               String purpose) {
            return keys.stream().filter(k -> k.getKeyState() == DeviceBusinessKey.KeyState.ACTIVE).findFirst();
        }

        @Override
        public Optional<DeviceBusinessKey> findByRequestIdAndPurpose(String requestId, String purpose) {
            return Optional.empty();
        }

        @Override
        public Optional<DeviceBusinessKey> findById(Long id) {
            return Optional.empty();
        }

        @Override
        public Optional<DeviceBusinessKey> findByKeyIdForUpdate(String keyId) {
            return findByKeyId(keyId);
        }

        @Override
        public void save(DeviceBusinessKey key) {
            keys.add(key);
        }
    }

    static class InMemLeaseRepo implements KeyProvisioningLeaseRepository {
        final List<KeyProvisioningLease> leases = new ArrayList<>();

        @Override
        public Optional<KeyProvisioningLease> findByProvisioningAndSeq(Long provisioningId, int leaseSeq) {
            return leases.stream()
                    .filter(l -> provisioningId.equals(l.getProvisioningId()) && leaseSeq == l.getLeaseSeq())
                    .findFirst();
        }

        @Override
        public Optional<KeyProvisioningLease> findByMessageId(String messageId) {
            return leases.stream().filter(l -> messageId.equals(l.getMessageId())).findFirst();
        }

        @Override
        public void save(KeyProvisioningLease lease) {
            leases.add(lease);
        }
    }

    static class InMemEnrollmentRepo implements CredentialEnrollmentRepository {
        final List<CredentialEnrollment> enrollments = new ArrayList<>();

        @Override
        public Optional<CredentialEnrollment> findByRequestId(String requestId) {
            return enrollments.stream().filter(e -> requestId.equals(e.getRequestId())).findFirst();
        }

        @Override
        public CertificatePage page(CertificateQuery query) {
            return new CertificatePage(enrollments, enrollments.size());
        }

        @Override
        public Optional<CredentialEnrollment> findByCertSn(String certSn) {
            return Optional.empty();
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
            return Optional.empty();
        }

        @Override
        public List<CredentialEnrollment> listByDeviceSn(String deviceSn) {
            return List.of();
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
        }

        @Override
        public void supersedeActiveByDeviceSnAndProfile(String deviceSn, String profile, String excludeRequestId) {
        }
    }
}
