package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateCompensateVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.CsrTestSupport;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertEnrollmentAdapter;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * 人工补申请前置门禁测试（SEC-VIAM-DSN-CR-004 / D-VIAM-023/024/027 / T26～T30）。
 * <p>
 * 覆盖：IVI 正常链路、类别—Profile 交叉/未知组合（702207）、VIN/SN/类别/主体一致性
 * （702202/702203/702002）、CSR 门禁（702204/702205/702206）、requestId 幂等与冲突（702215）、
 * TBOX 回归。适配层以 Mock 注入（本类只验证进入 PKI 前的门禁与审计）。
 * </p>
 * <p>
 * 复用 {@link CertificateManagementAppServiceTest} 的内存仓储替身，避免夹具重复。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SEC-VIAM-DSN-CR-004 人工补申请门禁")
class CertificateCompensationGateTest {

    private static final String VIN = "VIN1";

    @Mock
    private CertEnrollmentAdapter adapter;

    private CertificateManagementAppServiceTest.InMemEnrollmentRepo enrollmentRepo;
    private CertificateManagementAppServiceTest.InMemOperationRepo operationRepo;
    private CertificateManagementAppServiceTest.InMemPrincipalRepo principalRepo;
    private CertificateManagementAppServiceTest.InMemMappingRepo mappingRepo;
    private CertificateProvisioningAppService service;

    @BeforeEach
    void setUp() {
        enrollmentRepo = new CertificateManagementAppServiceTest.InMemEnrollmentRepo();
        operationRepo = new CertificateManagementAppServiceTest.InMemOperationRepo();
        principalRepo = new CertificateManagementAppServiceTest.InMemPrincipalRepo();
        mappingRepo = new CertificateManagementAppServiceTest.InMemMappingRepo();
        service = new CertificateProvisioningAppService(enrollmentRepo, principalRepo, mappingRepo,
                operationRepo, new CertificateOperationRecorder(operationRepo), adapter);
    }

    // ==================== T26：IVI 正常链路 ====================

    @Test
    @DisplayName("T26 IVI 正常补申请：类别/Profile 规范化落库，进入同一 compensate 审计")
    void iviCompensatePassesGatesAndAudits() {
        givenPrincipal("UID-IVI", "SN-IVI", "IVI");
        String csr = CsrTestSupport.csr("UID-IVI");

        CertificateOperationResultVo result = service.compensate(
                vo("MPT-IVI-1", "IVI", "IVI_DEVICE_IDENTITY", "SN-IVI", csr),
                "99", "运维A", "10.0.0.1", "JUnit");

        assertEquals("MPT-IVI-1", result.getRequestId());
        assertEquals("REQUESTED", result.getStatus());
        assertEquals("IVI", enrollmentRepo.enrollments.get(0).getDeviceCategory());
        assertEquals("IVI_DEVICE_IDENTITY", enrollmentRepo.enrollments.get(0).getCertificateProfile());
        assertEquals("MPT_COMPENSATION", enrollmentRepo.enrollments.get(0).getSourceSystem());
        assertNotNull(enrollmentRepo.enrollments.get(0).getCsrFingerprint());
        assertEquals(1, operationRepo.operations.size());
        assertEquals(CertificateOperation.Action.COMPENSATE, operationRepo.operations.get(0).getAction());
        assertEquals("99", operationRepo.operations.get(0).getOperatorId());
        verify(adapter, times(1)).apply(any(), anyString());
    }

    @Test
    @DisplayName("T26 类别/Profile 规范化后匹配（小写输入同样放行）")
    void categoryAndProfileAreNormalized() {
        givenPrincipal("UID-1", "SN-1", "TBOX");

        service.compensate(vo("MPT-N-1", " tbox ", "tbox_tsp_client", "SN-1",
                CsrTestSupport.csr("UID-1")), "99", null, null, null);

        assertEquals("TBOX", enrollmentRepo.enrollments.get(0).getDeviceCategory());
        assertEquals("TBOX_TSP_CLIENT", enrollmentRepo.enrollments.get(0).getCertificateProfile());
    }

    // ==================== T27：类别—Profile 治理 ====================

    @Test
    @DisplayName("T27 交叉组合 TBOX+IVI Profile 拒绝 702207 且不进入 PKI")
    void crossCategoryProfileRejected() {
        assertGateError(ViamErrorCode.CERTIFICATE_PROFILE_NOT_ALLOWED,
                vo("MPT-X-1", "TBOX", "IVI_DEVICE_IDENTITY", "SN-1", CsrTestSupport.csr("UID-1")));
        assertGateError(ViamErrorCode.CERTIFICATE_PROFILE_NOT_ALLOWED,
                vo("MPT-X-2", "IVI", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-1")));
    }

    @Test
    @DisplayName("T27 未知类别/未知 Profile 拒绝 702207")
    void unknownCategoryOrProfileRejected() {
        assertGateError(ViamErrorCode.CERTIFICATE_PROFILE_NOT_ALLOWED,
                vo("MPT-X-3", "CGW", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-1")));
        assertGateError(ViamErrorCode.CERTIFICATE_PROFILE_NOT_ALLOWED,
                vo("MPT-X-4", "IVI", "IVI_OTHER", "SN-1", CsrTestSupport.csr("UID-1")));
    }

    // ==================== T27：CSR 门禁 ====================

    @Test
    @DisplayName("T27 CN=deviceSn 拒绝 702205")
    void csrCommonNameEqualsDeviceSnRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_SUBJECT_MISMATCH,
                vo("MPT-C-1", "TBOX", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("SN-1")));
    }

    @Test
    @DisplayName("T27 CN 缺失或重复拒绝 702205")
    void csrCommonNameMissingOrDuplicatedRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        String missingCn = CsrTestSupport.csr(new X500Name("O=OpenIOV"), CsrTestSupport.keyPair());
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_SUBJECT_MISMATCH,
                vo("MPT-C-2", "TBOX", "TBOX_TSP_CLIENT", "SN-1", missingCn));

        String duplicatedCn = CsrTestSupport.csr(new X500Name("CN=UID-1,CN=UID-1"),
                CsrTestSupport.keyPair());
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_SUBJECT_MISMATCH,
                vo("MPT-C-3", "TBOX", "TBOX_TSP_CLIENT", "SN-1", duplicatedCn));
    }

    @Test
    @DisplayName("T27 CN 与目标 hsmUid 不一致拒绝 702205")
    void csrCommonNameMismatchedRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_SUBJECT_MISMATCH,
                vo("MPT-C-4", "TBOX", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-OTHER")));
    }

    @Test
    @DisplayName("T27 CSR 含 VIN 拒绝 702206")
    void csrContainingVinRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_CONTAINS_VIN,
                vo("MPT-C-5", "TBOX", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-1", "OU=" + VIN)));
    }

    @Test
    @DisplayName("T27 CSR 非法（Base64/DER/自签名）拒绝 702204")
    void invalidCsrRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_INVALID,
                vo("MPT-C-6", "TBOX", "TBOX_TSP_CLIENT", "SN-1", "!!not-base64!!"));
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_INVALID,
                vo("MPT-C-7", "TBOX", "TBOX_TSP_CLIENT", "SN-1",
                        Base64.getEncoder().encodeToString(new byte[]{1, 2, 3})));

        byte[] der = Base64.getDecoder().decode(CsrTestSupport.csr("UID-1"));
        der[der.length - 1] = (byte) (der[der.length - 1] ^ 0xFF);
        assertServiceError(ViamErrorCode.CERTIFICATE_CSR_INVALID,
                vo("MPT-C-8", "TBOX", "TBOX_TSP_CLIENT", "SN-1",
                        Base64.getEncoder().encodeToString(der)));
    }

    // ==================== T28：绑定与主体一致性 ====================

    @Test
    @DisplayName("T28 SN 无 ACTIVE 映射拒绝 702202")
    void unboundDeviceSnRejected() {
        assertGateError(ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND,
                vo("MPT-B-1", "TBOX", "TBOX_TSP_CLIENT", "SN-NONE", CsrTestSupport.csr("UID-1")));
    }

    @Test
    @DisplayName("T28 请求 VIN 与 ACTIVE 映射不一致拒绝 702202")
    void vinMismatchRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        CertificateCompensateVo cmd = vo("MPT-B-2", "TBOX", "TBOX_TSP_CLIENT", "SN-1",
                CsrTestSupport.csr("UID-1"));
        cmd.setVin("VIN-OTHER");
        assertServiceError(ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND, cmd);
    }

    @Test
    @DisplayName("T28 请求类别与映射类别不一致拒绝 702203")
    void categoryMismatchRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        assertGateError(ViamErrorCode.CERTIFICATE_DEVICE_CATEGORY_MISMATCH,
                vo("MPT-B-3", "IVI", "IVI_DEVICE_IDENTITY", "SN-1", CsrTestSupport.csr("UID-1")));
    }

    @Test
    @DisplayName("T28 主体缺失或非 ACTIVE 失败关闭（702002）")
    void principalMissingOrInactiveRejected() {
        mappingRepo.mappings.add(mapping("P-GHOST", "SN-1", VIN, "TBOX"));
        assertGateError(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE,
                vo("MPT-B-4", "TBOX", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-1")));

        mappingRepo.mappings.clear();
        mappingRepo.mappings.add(mapping("P-UID-1", "SN-1", VIN, "TBOX"));
        principalRepo.principals.add(SecurityPrincipal.builder()
                .principalId("P-UID-1").hsmUid("UID-1")
                .state(SecurityPrincipal.PrincipalState.BLOCKED).build());
        assertGateError(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE,
                vo("MPT-B-5", "TBOX", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-1")));
    }

    // ==================== T29：幂等与冲突 ====================

    @Test
    @DisplayName("T29 同 requestId 同内容幂等返回既有结果，不重复签发")
    void idempotentReplayReturnsExisting() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        String csr = CsrTestSupport.csr("UID-1");
        service.compensate(vo("MPT-I-1", "TBOX", "TBOX_TSP_CLIENT", "SN-1", csr),
                "99", null, null, null);
        service.compensate(vo("MPT-I-1", "TBOX", "TBOX_TSP_CLIENT", "SN-1", csr),
                "99", null, null, null);

        verify(adapter, times(1)).apply(any(), anyString());
        assertEquals(1, enrollmentRepo.enrollments.size());
        assertEquals(2, operationRepo.operations.size());
        assertEquals(CertificateOperation.Result.SUCCESS, operationRepo.operations.get(0).getResult());
        assertEquals(CertificateOperation.Result.IDEMPOTENT_HIT, operationRepo.operations.get(1).getResult());
    }

    @Test
    @DisplayName("T29 同 requestId 不同内容拒绝 702215")
    void idempotencyConflictRejected() {
        givenPrincipal("UID-1", "SN-1", "TBOX");
        service.compensate(vo("MPT-I-2", "TBOX", "TBOX_TSP_CLIENT", "SN-1",
                CsrTestSupport.csr("UID-1")), "99", null, null, null);

        String differentCsr = CsrTestSupport.csr("UID-1");
        assertServiceError(ViamErrorCode.CERTIFICATE_REQUEST_IDEMPOTENCY_CONFLICT,
                vo("MPT-I-2", "TBOX", "TBOX_TSP_CLIENT", "SN-1", differentCsr));
        verify(adapter, times(1)).apply(any(), anyString());
    }

    // ==================== T30：TBOX 回归 ====================

    @Test
    @DisplayName("T30 TBOX 正常补申请行为不变（CN=hsmUid、同一端点语义、审计 COMPENSATE）")
    void tboxCompensateUnchanged() {
        givenPrincipal("UID-1", "SN-1", "TBOX");

        CertificateOperationResultVo result = service.compensate(
                vo("MPT-T-1", "TBOX", "TBOX_TSP_CLIENT", "SN-1", CsrTestSupport.csr("UID-1")),
                "99", "运维B", null, null);

        assertEquals("REQUESTED", result.getStatus());
        assertEquals("TBOX", enrollmentRepo.enrollments.get(0).getDeviceCategory());
        assertEquals("TBOX_TSP_CLIENT", enrollmentRepo.enrollments.get(0).getCertificateProfile());
        assertEquals(1, operationRepo.operations.size());
        assertTrue(operationRepo.operations.get(0).getRequestDigest().length() > 0);
        verify(adapter, times(1)).apply(any(), anyString());
    }

    // ==================== 夹具 ====================

    private void givenPrincipal(String hsmUid, String deviceSn, String deviceCategory) {
        principalRepo.principals.add(SecurityPrincipal.builder()
                .principalId("P-" + hsmUid).hsmUid(hsmUid)
                .state(SecurityPrincipal.PrincipalState.ACTIVE).build());
        mappingRepo.mappings.add(mapping("P-" + hsmUid, deviceSn, VIN, deviceCategory));
    }

    private static PrincipalAssetMapping mapping(String principalId, String deviceSn,
                                                 String vin, String deviceCategory) {
        return PrincipalAssetMapping.builder()
                .principalId(principalId).vin(vin).deviceSn(deviceSn)
                .deviceCategory(deviceCategory)
                .state(PrincipalAssetMapping.MappingState.ACTIVE).build();
    }

    private static CertificateCompensateVo vo(String requestId, String deviceCategory,
                                              String certificateProfile, String deviceSn, String csr) {
        return CertificateCompensateVo.builder()
                .vin(VIN).deviceCategory(deviceCategory).deviceSn(deviceSn)
                .certificateProfile(certificateProfile).csrDerBase64(csr)
                .requestId(requestId).ticketNo("T-1").reason("MES未达").build();
    }

    private void assertGateError(ViamErrorCode expected, CertificateCompensateVo cmd) {
        assertServiceError(expected, cmd);
        verifyNoInteractions(adapter);
    }

    private void assertServiceError(ViamErrorCode expected, CertificateCompensateVo cmd) {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> service.compensate(cmd, "99", null, null, null));
        assertEquals(expected.getCode(), ex.getCode());
    }
}
