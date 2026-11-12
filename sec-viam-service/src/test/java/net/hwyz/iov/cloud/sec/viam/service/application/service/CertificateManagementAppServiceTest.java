package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateCompensateVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateDetailVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateMaterialVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateReconcileVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateReissueVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificatePage;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificateQuery;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CertificateOperationRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertEnrollmentAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * 证书管理面应用服务测试（SEC-VIAM-DSN-CR-002 / T09–T14 / D-VIAM-011～016）。
 * <p>
 * 覆盖：分页查询、详情时间线、人工补申请主体解析、证书本体重取（含超期与审计失败 fail-closed）、
 * 重签新记录与旧记录终态、安装补录操作人服务端覆盖。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SEC-VIAM-DSN-CR-002 证书管理面")
class CertificateManagementAppServiceTest {

    @Mock
    private CertEnrollmentAdapter adapter;

    private InMemEnrollmentRepo enrollmentRepo;
    private InMemOperationRepo operationRepo;
    private InMemPrincipalRepo principalRepo;
    private InMemMappingRepo mappingRepo;
    private CertificateProvisioningAppService service;

    @BeforeEach
    void setUp() {
        enrollmentRepo = new InMemEnrollmentRepo();
        operationRepo = new InMemOperationRepo();
        principalRepo = new InMemPrincipalRepo();
        mappingRepo = new InMemMappingRepo();
        service = new CertificateProvisioningAppService(enrollmentRepo, principalRepo, mappingRepo,
                operationRepo, new CertificateOperationRecorder(operationRepo), adapter);
    }

    @Test
    @DisplayName("T09 分页查询返回条目与总数，且列表项不含证书本体")
    void searchReturnsItemsAndTotal() {
        enrollmentRepo.enrollments.add(activeEnrollment("REQ-1"));
        CertificatePage page = new CertificatePage(enrollmentRepo.enrollments, 1L);
        enrollmentRepo.pageResult = page;

        var result = service.search(new CertificateQuery("VIN1", null, null, null, null, null, null, null));

        assertEquals(1, result.getItems().size());
        assertEquals(1L, result.getTotal());
        assertEquals("REQ-1", result.getItems().get(0).getRequestId());
    }

    @Test
    @DisplayName("T10 详情按 requestId 返回且时间线来自审计仓储")
    void detailIncludesOperationTimeline() {
        enrollmentRepo.enrollments.add(activeEnrollment("REQ-1"));
        operationRepo.operations.add(operation("REQ-1", CertificateOperation.Action.RECONCILE));

        CertificateDetailVo detail = service.detail("REQ-1");

        assertEquals("REQ-1", detail.getRequestId());
        assertEquals(1, detail.getOperations().size());
        assertEquals("RECONCILE", detail.getOperations().get(0).getAction());
    }

    @Test
    @DisplayName("T10 详情 requestId 不存在返回既有 702213 语义")
    void detailRejectsUnknownRequestId() {
        ViamServiceException ex = assertThrows(ViamServiceException.class, () -> service.detail("NOPE"));
        assertEquals(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T11 人工补申请：主体由设备资产映射解析，落 COMPENSATE 审计且来源为 MPT_COMPENSATION")
    void compensateResolvesPrincipalByDeviceSnAndAudits() {
        principalRepo.principals.add(activePrincipal("UID-1"));
        mappingRepo.mappings.add(mapping("UID-1", "SN-1"));

        CertificateOperationResultVo result = service.compensate(compensateVo("MPT-CERT-1"),
                "99", "运维A", "10.0.0.1", "JUnit");

        assertEquals("MPT-CERT-1", result.getRequestId());
        assertEquals("REQUESTED", result.getStatus());
        assertEquals("MPT_COMPENSATION", enrollmentRepo.enrollments.get(0).getSourceSystem());
        assertEquals(1, operationRepo.operations.size());
        assertEquals(CertificateOperation.Action.COMPENSATE, operationRepo.operations.get(0).getAction());
        assertEquals("99", operationRepo.operations.get(0).getOperatorId());
        // 审计摘要不含 CSR 全文
        assertNotNull(operationRepo.operations.get(0).getRequestDigest());
        assertFalse(operationRepo.operations.get(0).getRequestDigest().contains("CSRDATA"));
    }

    @Test
    @DisplayName("T11 人工补申请：无受信资产映射时拒绝（不得仅凭自报身份）")
    void compensateRejectsWhenNoActiveMapping() {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.compensate(compensateVo("MPT-CERT-2"), "99", null, null, null));
        assertEquals(ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND.getCode(), ex.getCode());
        assertTrue(operationRepo.operations.isEmpty());
    }

    @Test
    @DisplayName("T12 安装补录：操作人取服务端参数，忽略请求体自报 operatorId")
    void confirmInstalledOverridesSelfReportedOperator() {
        enrollmentRepo.enrollments.add(enrollment("REQ-1", CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED));
        CertificateConfirmInstalledVo cmd = CertificateConfirmInstalledVo.builder()
                .requestId("REQ-1").result("SUCCESS").reason("现场补录").ticketNo("T-1")
                .operatorId("SELF-REPORTED").build();

        service.confirmInstalled(cmd, "100", "10.0.0.2", "JUnit");

        assertEquals("100", enrollmentRepo.enrollments.get(0).getLastOperator());
        assertEquals(CredentialEnrollment.CertificateState.ACTIVE, enrollmentRepo.enrollments.get(0).getCertStatus());
        assertEquals(CertificateOperation.Action.CONFIRM_INSTALLED, operationRepo.operations.get(0).getAction());
        assertEquals("100", operationRepo.operations.get(0).getOperatorId());
    }

    @Test
    @DisplayName("T12 安装补录：certSn 与记录不一致时拒绝（702211）")
    void confirmInstalledRejectsCertSnMismatch() {
        enrollmentRepo.enrollments.add(enrollment("REQ-1", CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED));
        CertificateConfirmInstalledVo cmd = CertificateConfirmInstalledVo.builder()
                .requestId("REQ-1").result("SUCCESS").certSn("deadbeef").reason("r").ticketNo("t").build();

        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.confirmInstalled(cmd, "100", null, null));
        assertEquals(ViamErrorCode.CERTIFICATE_INSTALL_CONFIRM_MISMATCH.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T13 证书本体重取：返回叶子与链 DER Base64 并落 QUERY_CERTIFICATE 审计")
    void queryCertificateMaterialReturnsDerAndAudits() {
        CredentialEnrollment active = activeEnrollment("REQ-1");
        active.setPkiRequestId("PKI-1");
        enrollmentRepo.enrollments.add(active);
        when(adapter.getCertificate("PKI-1")).thenReturn(issued());

        CertificateMaterialVo material = service.queryCertificateMaterial("REQ-1", "100", "10.0.0.3", "JUnit");

        assertEquals(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}), material.getCertificateDerBase64());
        assertEquals(1, material.getChainDerBase64().length);
        assertEquals(CertificateOperation.Action.QUERY_CERTIFICATE, operationRepo.operations.get(0).getAction());
    }

    @Test
    @DisplayName("T13 证书本体重取：PKI 无材料时明确失败（702221），不返回空成功")
    void queryCertificateMaterialFailsWhenPkiNoLongerKeepsIt() {
        CredentialEnrollment active = activeEnrollment("REQ-1");
        active.setPkiRequestId("PKI-GONE");
        enrollmentRepo.enrollments.add(active);
        when(adapter.getCertificate("PKI-GONE")).thenReturn(null);

        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.queryCertificateMaterial("REQ-1", "100", null, null));
        assertEquals(ViamErrorCode.CERTIFICATE_MATERIAL_NOT_RETRIEVABLE.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T13 证书本体重取：审计写入失败即失败，不返回证书材料（fail-closed）")
    void queryCertificateMaterialFailsClosedWhenAuditFails() {
        CredentialEnrollment active = activeEnrollment("REQ-1");
        active.setPkiRequestId("PKI-1");
        enrollmentRepo.enrollments.add(active);
        when(adapter.getCertificate("PKI-1")).thenReturn(issued());
        operationRepo.failOnSave = true;

        assertThrows(IllegalStateException.class,
                () -> service.queryCertificateMaterial("REQ-1", "100", null, null));
    }

    @Test
    @DisplayName("T13 证书本体重取：状态不允许时拒绝（702212）")
    void queryCertificateMaterialRejectsNotIssuedState() {
        enrollmentRepo.enrollments.add(enrollment("REQ-1", CredentialEnrollment.CertificateState.REQUESTED));
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.queryCertificateMaterial("REQ-1", "100", null, null));
        assertEquals(ViamErrorCode.CERTIFICATE_STATUS_NOT_ALLOWED.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("T14 重新签发：旧记录进入 SUPERSEDED，新记录独立 requestId 并落 REISSUE 审计")
    void reissueCreatesNewRecordAndSupersedesOld() {
        CredentialEnrollment old = activeEnrollment("REQ-OLD");
        old.setHsmUid("UID-1");
        enrollmentRepo.enrollments.add(old);
        principalRepo.principals.add(activePrincipal("UID-1"));

        CertificateOperationResultVo result = service.reissue("REQ-OLD",
                reissueVo("REQ-NEW"), "100", "10.0.0.4", "JUnit");

        assertEquals("REQ-NEW", result.getRequestId());
        CredentialEnrollment superseded = enrollmentRepo.findByRequestId("REQ-OLD").orElseThrow();
        assertEquals(CredentialEnrollment.CertificateState.SUPERSEDED, superseded.getCertStatus());
        assertNotNull(enrollmentRepo.findByRequestId("REQ-NEW").orElse(null));
        assertEquals(CertificateOperation.Action.REISSUE, operationRepo.operations.get(0).getAction());
        assertEquals("ACTIVE", operationRepo.operations.get(0).getBeforeStatus());
    }

    @Test
    @DisplayName("T14 重新签发：非定案态拒绝（702212），不产生新记录")
    void reissueRejectsNonTerminalState() {
        enrollmentRepo.enrollments.add(enrollment("REQ-1", CredentialEnrollment.CertificateState.REQUESTED));
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.reissue("REQ-1", reissueVo("REQ-2"), "100", null, null));
        assertEquals(ViamErrorCode.CERTIFICATE_STATUS_NOT_ALLOWED.getCode(), ex.getCode());
        assertEquals(1, enrollmentRepo.enrollments.size());
    }

    @Test
    @DisplayName("T12 对账：状态不允许时由既有语义拒绝，且不落审计")
    void reconcileRejectsWhenStateNotAllowed() {
        enrollmentRepo.enrollments.add(activeEnrollment("REQ-1"));
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.reconcileForMpt("REQ-1", new CertificateReconcileVo("r", "t", null),
                        "100", null, null));
        assertEquals(ViamErrorCode.CERTIFICATE_COMPENSATION_NOT_ALLOWED.getCode(), ex.getCode());
        assertTrue(operationRepo.operations.isEmpty());
    }

    // ================= 测试夹具 =================

    private static CertificateCompensateVo compensateVo(String requestId) {
        return CertificateCompensateVo.builder()
                .vin("VIN1").deviceCategory("TBOX").deviceSn("SN-1")
                .certificateProfile("TBOX_TSP_CLIENT").csrDerBase64("CSRDATA")
                .requestId(requestId).ticketNo("T-1").reason("MES未达").build();
    }

    private static CertificateReissueVo reissueVo(String requestId) {
        return CertificateReissueVo.builder()
                .csrDerBase64("CSRDATA").reason("换证").ticketNo("T-2").requestId(requestId).build();
    }

    private static CredentialEnrollment enrollment(String requestId, CredentialEnrollment.CertificateState state) {
        return CredentialEnrollment.builder()
                .requestId(requestId).vin("VIN1").deviceCategory("TBOX").deviceSn("SN-1")
                .certificateProfile("TBOX_TSP_CLIENT").certSn("abc123").hsmUid("UID-1")
                .sourceSystem("MES").certStatus(state).build();
    }

    private static CredentialEnrollment activeEnrollment(String requestId) {
        return enrollment(requestId, CredentialEnrollment.CertificateState.ACTIVE);
    }

    private static SecurityPrincipal activePrincipal(String hsmUid) {
        return SecurityPrincipal.builder()
                .principalId("P-" + hsmUid).hsmUid(hsmUid)
                .state(SecurityPrincipal.PrincipalState.ACTIVE).build();
    }

    private static PrincipalAssetMapping mapping(String hsmUid, String deviceSn) {
        return PrincipalAssetMapping.builder()
                .principalId("P-" + hsmUid).vin("VIN1").deviceSn(deviceSn)
                .deviceCategory("TBOX").state(PrincipalAssetMapping.MappingState.ACTIVE).build();
    }

    private static CertificateOperation operation(String requestId, CertificateOperation.Action action) {
        return CertificateOperation.builder()
                .operationId(requestId + ":" + action + ":1").requestId(requestId).action(action)
                .result(CertificateOperation.Result.SUCCESS).occurredAt(Instant.now()).build();
    }

    private static IssuedCertificate issued() {
        return new IssuedCertificate(new byte[]{1, 2, 3}, List.of(new byte[]{4, 5}),
                "ABC123", Instant.now(), Instant.now().plusSeconds(3600), "fp");
    }

    // ================= 内存替身 =================

    static class InMemEnrollmentRepo implements CredentialEnrollmentRepository {
        final List<CredentialEnrollment> enrollments = new ArrayList<>();
        CertificatePage pageResult = new CertificatePage(List.of(), 0L);

        @Override
        public Optional<CredentialEnrollment> findByRequestId(String requestId) {
            return enrollments.stream().filter(e -> requestId.equals(e.getRequestId())).findFirst();
        }

        @Override
        public CertificatePage page(CertificateQuery query) {
            return pageResult;
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
            return enrollments.stream()
                    .filter(e -> e.getCertStatus() == CredentialEnrollment.CertificateState.ACTIVE)
                    .findFirst();
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
            // 内存替身保留引用，无需替换
        }

        @Override
        public void supersedeActiveByDeviceSnAndProfile(String deviceSn, String profile, String excludeRequestId) {
            enrollments.stream()
                    .filter(e -> deviceSn.equals(e.getDeviceSn()))
                    .filter(e -> !excludeRequestId.equals(e.getRequestId()))
                    .filter(e -> e.getCertStatus() == CredentialEnrollment.CertificateState.ACTIVE)
                    .forEach(e -> e.setCertStatus(CredentialEnrollment.CertificateState.SUPERSEDED));
        }
    }

    static class InMemOperationRepo implements CertificateOperationRepository {
        final List<CertificateOperation> operations = new ArrayList<>();
        boolean failOnSave = false;

        @Override
        public Optional<CertificateOperation> findByOperationId(String operationId) {
            return operations.stream().filter(o -> operationId.equals(o.getOperationId())).findFirst();
        }

        @Override
        public List<CertificateOperation> listByRequestId(String requestId) {
            return operations.stream().filter(o -> requestId.equals(o.getRequestId())).toList();
        }

        @Override
        public void save(CertificateOperation operation) {
            if (failOnSave) {
                throw new IllegalStateException("审计写入失败（模拟）");
            }
            operations.add(operation);
        }
    }

    static class InMemPrincipalRepo implements SecurityPrincipalRepository {
        final List<SecurityPrincipal> principals = new ArrayList<>();

        @Override
        public Optional<SecurityPrincipal> findByPrincipalId(String principalId) {
            return principals.stream().filter(p -> principalId.equals(p.getPrincipalId())).findFirst();
        }

        @Override
        public Optional<SecurityPrincipal> findByHsmUid(String hsmUid) {
            return principals.stream().filter(p -> hsmUid != null && hsmUid.equalsIgnoreCase(p.getHsmUid()))
                    .findFirst();
        }

        @Override
        public void save(SecurityPrincipal principal) {
            principals.add(principal);
        }

        @Override
        public List<SecurityPrincipal> listAll(int offset, int limit) {
            return principals;
        }
    }

    static class InMemMappingRepo implements PrincipalAssetMappingRepository {
        final List<PrincipalAssetMapping> mappings = new ArrayList<>();

        @Override
        public Optional<PrincipalAssetMapping> findByPrincipalAndVin(String principalId, String vin) {
            return mappings.stream().filter(m -> principalId.equals(m.getPrincipalId())).findFirst();
        }

        @Override
        public List<PrincipalAssetMapping> listActiveByPrincipalId(String principalId) {
            return List.of();
        }

        @Override
        public List<PrincipalAssetMapping> listActiveByVin(String vin) {
            return List.of();
        }

        @Override
        public Optional<PrincipalAssetMapping> findActiveByDeviceSn(String deviceSn) {
            return mappings.stream().filter(m -> deviceSn.equals(m.getDeviceSn())).findFirst();
        }

        @Override
        public void save(PrincipalAssetMapping mapping) {
            mappings.add(mapping);
        }
    }
}
