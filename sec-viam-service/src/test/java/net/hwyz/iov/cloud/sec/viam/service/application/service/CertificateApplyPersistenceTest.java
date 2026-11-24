package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CertificateOperationRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertEnrollmentAdapter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * 证书申请落库测试（SEC-VIAM-DSN-CR-006 修复：签发成功路径未持久化）
 * <p>
 * 线上缺陷：`apply` 成功时只更新内存对象，未 `enrollmentRepository.update`，
 * DB 永停 REQUESTED，导致无法 confirmInstalled（状态门禁要求 ISSUED_NOT_CONFIRMED）。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("证书申请结果落库")
class CertificateApplyPersistenceTest {

    @Mock
    private CredentialEnrollmentRepository enrollmentRepository;

    @Mock
    private SecurityPrincipalRepository principalRepository;

    @Mock
    private PrincipalAssetMappingRepository assetMappingRepository;

    @Mock
    private CertificateOperationRepository certificateOperationRepository;

    @Mock
    private CertificateOperationRecorder operationRecorder;

    @Mock
    private CertEnrollmentAdapter certEnrollmentAdapter;

    @InjectMocks
    private CertificateProvisioningAppService appService;

    private static CertificateApplyVo command() {
        return CertificateApplyVo.builder()
                .requestId("REQ-1")
                .vin("VIN1")
                .deviceCategory("IVI")
                .deviceSn("SN-IVI")
                .ecuUid("00000005AA0000000000000000000001")
                .certificateProfile("IVI_DEVICE_IDENTITY")
                .csrDerBase64("Y3Ny")
                .sourceSystem("MPT_COMPENSATION")
                .build();
    }

    private void stubApplyPrerequisites() {
        when(enrollmentRepository.findByRequestId("REQ-1")).thenReturn(Optional.empty());
        when(principalRepository.findByHsmUid(anyString()))
                .thenReturn(Optional.of(SecurityPrincipal.builder()
                        .principalId("P1").hsmUid("00000005AA0000000000000000000001")
                        .state(SecurityPrincipal.PrincipalState.ACTIVE).build()));
        when(enrollmentRepository.findByVinAndUidAndSpkiAndProfile(any(), any(), any(), any()))
                .thenReturn(Optional.empty());
    }

    @Test
    @DisplayName("签发成功：状态写入 ISSUED_NOT_CONFIRMED 并落库")
    void apply_shouldPersistIssuedState() {
        stubApplyPrerequisites();
        doAnswer(invocation -> {
            CredentialEnrollment e = invocation.getArgument(0);
            e.setCertSn("a67d63afe032a2523583a7b3ece254d0");
            e.setCertStatus(CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED);
            return null;
        }).when(certEnrollmentAdapter).apply(any(), anyString());

        CertificateApplyResultVo result = appService.apply(command());

        assertEquals("ISSUED_NOT_CONFIRMED", result.getStatus());
        assertEquals("a67d63afe032a2523583a7b3ece254d0", result.getCertSn());
        verify(enrollmentRepository).update(any(CredentialEnrollment.class));
    }

    @Test
    @DisplayName("PKI 结果未知：转 PENDING_RECONCILE 并落库")
    void apply_shouldPersistPendingReconcileWhenOutcomeUnknown() {
        stubApplyPrerequisites();
        doThrow(new PkiOutcomeUnknownException("timeout"))
                .when(certEnrollmentAdapter).apply(any(), anyString());

        CertificateApplyResultVo result = appService.apply(command());

        assertEquals("PENDING_RECONCILE", result.getStatus());
        verify(enrollmentRepository).update(any(CredentialEnrollment.class));
    }

    @Test
    @DisplayName("Profile 未登记：标记 FAILED 并返回 702207")
    void apply_shouldMarkFailedWhenProfileNotAllowed() {
        stubApplyPrerequisites();
        doThrow(new CertificateProfileNotAllowedException("no policy"))
                .when(certEnrollmentAdapter).apply(any(), anyString());

        ViamServiceException ex = assertThrows(ViamServiceException.class, () -> appService.apply(command()));

        assertEquals(ViamErrorCode.CERTIFICATE_PROFILE_NOT_ALLOWED.getCode(), ex.getCode());
        verify(enrollmentRepository).update(argThat(e ->
                e.getCertStatus() == CredentialEnrollment.CertificateState.FAILED));
    }

    @Test
    @DisplayName("幂等：同 requestId 已存在直接返回既有结果，不调 PKI")
    void apply_shouldReturnExistingWhenDuplicateRequestId() {
        CredentialEnrollment existing = CredentialEnrollment.builder()
                .requestId("REQ-1").certStatus(CredentialEnrollment.CertificateState.ACTIVE).build();
        when(enrollmentRepository.findByRequestId("REQ-1")).thenReturn(Optional.of(existing));

        CertificateApplyResultVo result = appService.apply(command());

        assertEquals("ACTIVE", result.getStatus());
        verify(certEnrollmentAdapter, never()).apply(any(), anyString());
    }
}
