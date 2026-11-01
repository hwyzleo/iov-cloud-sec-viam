package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionCheckVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceAdmissionResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionDecision;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionReason;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DecisionAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DecisionAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertificateVerificationAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * 准入裁决应用服务单元测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-004 / T01）
 * <p>
 * fail-closed 语义：UID 未知拒绝、身份不一致拒绝、PKI 依赖不可用拒绝（不降级 ALLOW）。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DeviceAdmissionAppServiceTest {

    private static final String UID = "HSM-0001";
    private static final String VIN = "VIN0000000000001";
    private static final String SN = "SN-0001";

    @Mock
    private SecurityPrincipalRepository principalRepository;
    @Mock
    private PrincipalAssetMappingRepository mappingRepository;
    @Mock
    private DeviceOnboardingRepository onboardingRepository;
    @Mock
    private DecisionAuditRepository decisionAuditRepository;
    @Mock
    private CertificateVerificationAdapter certificateVerificationAdapter;

    @InjectMocks
    private DeviceAdmissionAppService appService;

    private DeviceAdmissionCheckVo request() {
        return DeviceAdmissionCheckVo.builder()
                .uid(UID)
                .certSerial("0a1b2c")
                .certFingerprint("fp")
                .leafCertificateDer("AQID")
                .ts(Instant.parse("2026-11-01T10:00:00Z"))
                .build();
    }

    private SecurityPrincipal activePrincipal() {
        return SecurityPrincipal.builder()
                .principalId("PR-001")
                .hsmUid(UID)
                .state(SecurityPrincipal.PrincipalState.ACTIVE)
                .build();
    }

    private PrincipalAssetMapping activeMapping() {
        return PrincipalAssetMapping.builder()
                .principalId("PR-001")
                .vin(VIN)
                .deviceSn(SN)
                .bindingVersion(1L)
                .state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build();
    }

    @Test
    void decide_uidUnknownDeniesFailClosed() {
        when(principalRepository.findByHsmUid(anyString())).thenReturn(Optional.empty());
        DeviceAdmissionResultVo result = appService.decide(request(), "VAGW");
        assertEquals(AdmissionDecision.DENY, result.getDecision());
        assertEquals(AdmissionReason.UID_UNKNOWN, result.getReason());
        assertNotNull(result.getAdmissionDecisionId());
    }

    @Test
    void decide_pkiDependencyUnavailableDenies() throws Exception {
        when(principalRepository.findByHsmUid(anyString())).thenReturn(Optional.of(activePrincipal()));
        when(mappingRepository.listActiveByPrincipalId(anyString())).thenReturn(List.of(activeMapping()));
        when(certificateVerificationAdapter.verify(anyString(), anyString(), anyString(), any()))
                .thenThrow(new CertificateVerificationAdapter.ViamPkiDependencyUnavailable("PKI不可用"));
        DeviceAdmissionResultVo result = appService.decide(request(), "VAGW");
        assertEquals(AdmissionDecision.DENY, result.getDecision());
        assertEquals(AdmissionReason.DEPENDENCY_UNAVAILABLE, result.getReason());
    }

    @Test
    void decide_identityMismatchDenies() throws Exception {
        when(principalRepository.findByHsmUid(anyString())).thenReturn(Optional.of(activePrincipal()));
        when(mappingRepository.listActiveByPrincipalId(anyString())).thenReturn(List.of(activeMapping()));
        when(certificateVerificationAdapter.verify(anyString(), anyString(), anyString(), any()))
                .thenReturn(new CertificateVerificationAdapter.CertificateVerificationResult(
                        net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus.VALID,
                        "OTHER-UID", null, null, Instant.now()));
        DeviceAdmissionResultVo result = appService.decide(request(), "VAGW");
        assertEquals(AdmissionDecision.DENY, result.getDecision());
        assertEquals(AdmissionReason.IDENTITY_MISMATCH, result.getReason());
    }

    @Test
    void decide_allowWithSnapshotEvidence() throws Exception {
        when(principalRepository.findByHsmUid(anyString())).thenReturn(Optional.of(activePrincipal()));
        when(mappingRepository.listActiveByPrincipalId(anyString())).thenReturn(List.of(activeMapping()));
        when(onboardingRepository.findByPrincipalId(anyString())).thenReturn(Optional.of(
                DeviceOnboarding.builder()
                        .principalId("PR-001")
                        .state(DeviceOnboarding.OnboardingState.ACTIVE)
                        .build()));
        when(certificateVerificationAdapter.verify(anyString(), anyString(), anyString(), any()))
                .thenReturn(new CertificateVerificationAdapter.CertificateVerificationResult(
                        net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus.VALID,
                        UID, null, Instant.parse("2027-01-01T00:00:00Z"), Instant.now()));
        DeviceAdmissionResultVo result = appService.decide(request(), "VAGW");
        assertEquals(AdmissionDecision.ALLOW, result.getDecision());
        assertEquals(AdmissionReason.NONE, result.getReason());
        assertNotNull(result.getAdmissionDecisionId());
        // 准入审计必须含不可变快照（成功接入证据）
        org.mockito.Mockito.verify(decisionAuditRepository).save(any(DecisionAudit.class));
    }
}
