package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofReasonCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofType;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofAuditRecorder;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofMetrics;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofNonceStore;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofProperties;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofRateLimiter;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofInvalidException;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofEvidence;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofVerifier;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 设备证明校验应用服务单元测试（SEC-VIAM-DSN-CR-003 / TC-VIAM-3-01～06）。
 * <p>
 * 覆盖四类结论、nonce 重放、限流、依赖不可用 fail-closed、只读幂等（不写设备状态）、
 * 审计脱敏（只落摘要）。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DeviceProofVerifyAppServiceTest {

    private static final String UID = "HSM-0001";
    private static final String PRINCIPAL_ID = "PR-0001";
    private static final String SN = "SN-0001";
    private static final String NONCE = "nonce-0123456789abcdef";
    private static final String PROOF = "AQIDBA==";

    @Mock
    private DeviceProofVerifier deviceProofVerifier;
    @Mock
    private SecurityPrincipalRepository principalRepository;
    @Mock
    private PrincipalAssetMappingRepository mappingRepository;
    @Mock
    private DeviceOnboardingRepository onboardingRepository;
    @Mock
    private DeviceProofNonceStore nonceStore;
    @Mock
    private DeviceProofRateLimiter rateLimiter;
    @Mock
    private DeviceProofAuditRecorder auditRecorder;
    @Mock
    private DeviceProofMetrics metrics;

    private DeviceProofProperties properties;

    private DeviceProofVerifyAppService appService;

    @BeforeEach
    void setUp() {
        properties = new DeviceProofProperties();
        appService = new DeviceProofVerifyAppService(deviceProofVerifier, principalRepository, mappingRepository,
                onboardingRepository, nonceStore, rateLimiter, auditRecorder, metrics, properties);
    }

    private DeviceProofVerifyRequestVo request(DeviceProofType type, String deviceId) {
        return DeviceProofVerifyRequestVo.builder()
                .proofType(type.name())
                .proof(PROOF)
                .nonce(NONCE)
                .deviceId(deviceId)
                .build();
    }

    private SecurityPrincipal principal(SecurityPrincipal.PrincipalState state) {
        return SecurityPrincipal.builder()
                .principalId(PRINCIPAL_ID)
                .hsmUid(UID)
                .state(state)
                .build();
    }

    private PrincipalAssetMapping mapping() {
        return PrincipalAssetMapping.builder()
                .principalId(PRINCIPAL_ID)
                .deviceSn(SN)
                .vin("VIN-SHOULD-NOT-LEAK")
                .state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build();
    }

    private DeviceProofEvidence evidence() {
        return new DeviceProofEvidence(UID, "0a1b2c", "fp", SN, null, Instant.now());
    }

    private void allowAll() {
        when(rateLimiter.tryAcquire(anyString(), any(), any())).thenReturn(true);
        when(nonceStore.consume(anyString())).thenReturn(true);
    }

    @Test
    @DisplayName("TC-VIAM-3-01 有效证明：返回主体/设备SN/状态，且不返回VIN")
    void validProofReturnsRegisteredFacts() {
        allowAll();
        when(deviceProofVerifier.verify(eq(DeviceProofType.MTLS_CERT), any(), eq(NONCE), isNull(), any()))
                .thenReturn(evidence());
        when(principalRepository.findByHsmUid(UID)).thenReturn(Optional.of(principal(SecurityPrincipal.PrincipalState.ACTIVE)));
        when(mappingRepository.listActiveByPrincipalId(PRINCIPAL_ID)).thenReturn(List.of(mapping()));
        when(onboardingRepository.findByPrincipalId(PRINCIPAL_ID))
                .thenReturn(Optional.of(DeviceOnboarding.builder()
                        .principalId(PRINCIPAL_ID)
                        .state(DeviceOnboarding.OnboardingState.ACTIVE)
                        .build()));

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertTrue(result.isValid());
        assertEquals(DeviceProofReasonCode.PROOF_VALID.name(), result.getReasonCode());
        assertEquals(PRINCIPAL_ID, result.getDevicePrincipal());
        assertEquals(SN, result.getDeviceSn());
        assertEquals("ACTIVE", result.getDeviceStatus());
        assertNotNull(result.getVerifiedAt());
        // 只读幂等：不写任何安全事实；审计只落摘要（VIN 不进入结论）
        verify(principalRepository, never()).save(any());
        verify(mappingRepository, never()).save(any());
    }

    @Test
    @DisplayName("TC-VIAM-3-02 证明无效（证书/签名校验失败）→ PROOF_INVALID")
    void invalidProofMapsToProofInvalid() {
        allowAll();
        when(deviceProofVerifier.verify(any(), any(), anyString(), any(), any()))
                .thenThrow(new DeviceProofInvalidException("证书已被吊销"));

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.PROOF_INVALID.name(), result.getReasonCode());
        assertNull(result.getDevicePrincipal());
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(auditRecorder).record(anyString(), anyString(), isNull(), anyString(), any(), any(), any(),
                eq("PROOF_INVALID"), code.capture(), anyLong(), any());
        assertEquals("702721", code.getValue());
    }

    @Test
    @DisplayName("TC-VIAM-3-03 nonce 重放 → 拒绝且记录 702722（不回滚、不重复校验）")
    void nonceReplayRejected() {
        when(rateLimiter.tryAcquire(anyString(), any(), any())).thenReturn(true);
        when(nonceStore.consume(NONCE)).thenReturn(false);
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.PROOF_INVALID.name(), result.getReasonCode());
        verify(deviceProofVerifier, never()).verify(any(), any(), anyString(), any(), any());
        verify(metrics).recordNonceReplay();
        verify(auditRecorder).record(anyString(), anyString(), isNull(), anyString(), any(), any(), any(),
                eq("PROOF_INVALID"), code.capture(), anyLong(), any());
        assertEquals("702722", code.getValue());
    }

    @Test
    @DisplayName("TC-VIAM-3-03 缺失/非法参数 → 702720（参数错误，不返回 valid=false 混淆）")
    void invalidParamRejectedWithParamError() {
        DeviceProofVerifyRequestVo unsupportedType = DeviceProofVerifyRequestVo.builder()
                .proofType("PKI").proof(PROOF).nonce(NONCE).build();
        ViamServiceException typeError = assertThrows(ViamServiceException.class,
                () -> appService.verify(unsupportedType, "CIAM"));
        assertEquals("702720", typeError.getCode());

        DeviceProofVerifyRequestVo badProof = request(DeviceProofType.MTLS_CERT, null);
        badProof.setProof("###not-base64###");
        ViamServiceException base64Error = assertThrows(ViamServiceException.class,
                () -> appService.verify(badProof, "CIAM"));
        assertEquals("702720", base64Error.getCode());

        ViamServiceException missingDevice = assertThrows(ViamServiceException.class,
                () -> appService.verify(request(DeviceProofType.KEY_SIGNATURE, null), "CIAM"));
        assertEquals("702720", missingDevice.getCode());
    }

    @Test
    @DisplayName("TC-VIAM-3-04 主体未登记/阻断/退役 → SUBJECT_UNAVAILABLE（702723）")
    void subjectUnavailable() {
        allowAll();
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);

        // 未登记
        when(deviceProofVerifier.verify(any(), any(), anyString(), any(), any())).thenReturn(evidence());
        when(principalRepository.findByHsmUid(UID)).thenReturn(Optional.empty());
        DeviceProofVerifyResultVo unregistered = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");
        assertFalse(unregistered.isValid());
        assertEquals(DeviceProofReasonCode.SUBJECT_UNAVAILABLE.name(), unregistered.getReasonCode());

        // 阻断
        when(principalRepository.findByHsmUid(UID))
                .thenReturn(Optional.of(principal(SecurityPrincipal.PrincipalState.BLOCKED)));
        DeviceProofVerifyResultVo blocked = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");
        assertEquals(DeviceProofReasonCode.SUBJECT_UNAVAILABLE.name(), blocked.getReasonCode());

        // 退役
        when(principalRepository.findByHsmUid(UID))
                .thenReturn(Optional.of(principal(SecurityPrincipal.PrincipalState.RETIRED)));
        DeviceProofVerifyResultVo retired = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");
        assertEquals(DeviceProofReasonCode.SUBJECT_UNAVAILABLE.name(), retired.getReasonCode());

        verify(auditRecorder, org.mockito.Mockito.atLeastOnce()).record(anyString(), anyString(), any(), anyString(),
                any(), any(), any(), eq("SUBJECT_UNAVAILABLE"), code.capture(), anyLong(), any());
        assertTrue(code.getAllValues().contains("702723"));
    }

    @Test
    @DisplayName("TC-VIAM-3-04 安全开通态阻断/退役 → SUBJECT_UNAVAILABLE")
    void onboardingBlockedOrRetiredSubjectUnavailable() {
        allowAll();
        when(deviceProofVerifier.verify(any(), any(), anyString(), any(), any())).thenReturn(evidence());
        when(principalRepository.findByHsmUid(UID))
                .thenReturn(Optional.of(principal(SecurityPrincipal.PrincipalState.ACTIVE)));
        when(mappingRepository.listActiveByPrincipalId(PRINCIPAL_ID)).thenReturn(List.of(mapping()));
        when(onboardingRepository.findByPrincipalId(PRINCIPAL_ID))
                .thenReturn(Optional.of(DeviceOnboarding.builder()
                        .principalId(PRINCIPAL_ID)
                        .state(DeviceOnboarding.OnboardingState.BLOCKED)
                        .build()));

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.SUBJECT_UNAVAILABLE.name(), result.getReasonCode());
    }

    @Test
    @DisplayName("TC-VIAM-3-04 依赖超时/不可用 → DEPENDENCY_UNAVAILABLE（702724，不伪装为证明无效）")
    void dependencyUnavailableFailClosed() {
        allowAll();
        when(deviceProofVerifier.verify(any(), any(), anyString(), any(), any()))
                .thenThrow(new DeviceProofDependencyException("PKI不可用"));
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE.name(), result.getReasonCode());
        verify(auditRecorder).record(anyString(), anyString(), isNull(), anyString(), any(), any(), any(),
                eq("DEPENDENCY_UNAVAILABLE"), code.capture(), anyLong(), any());
        assertEquals("702724", code.getValue());
    }

    @Test
    @DisplayName("TC-VIAM-3-04 nonce 存储依赖不可用 → DEPENDENCY_UNAVAILABLE")
    void nonceStoreUnavailableFailClosed() {
        when(rateLimiter.tryAcquire(anyString(), any(), any())).thenReturn(true);
        when(nonceStore.consume(anyString())).thenThrow(new DeviceProofDependencyException("Redis不可用"));

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE.name(), result.getReasonCode());
    }

    @Test
    @DisplayName("TC-VIAM-3-06 限流命中 → RATE_LIMITED（702725），不进入证明校验")
    void rateLimited() {
        when(rateLimiter.tryAcquire(anyString(), any(), any())).thenReturn(false);
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.RATE_LIMITED.name(), result.getReasonCode());
        verify(metrics).recordRateLimited();
        verify(nonceStore, never()).consume(anyString());
        verify(auditRecorder).record(anyString(), anyString(), isNull(), anyString(), any(), any(), any(),
                eq("RATE_LIMITED"), code.capture(), anyLong(), any());
        assertEquals("702725", code.getValue());
    }

    @Test
    @DisplayName("能力未启用 → DEPENDENCY_UNAVAILABLE（fail-closed，不返回通过）")
    void disabledFailClosed() {
        properties.setEnabled(false);

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, null), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE.name(), result.getReasonCode());
        verify(deviceProofVerifier, never()).verify(any(), any(), anyString(), any(), any());
    }

    @Test
    @DisplayName("deviceId 与证明主体不一致 → PROOF_INVALID（不接受调用方声明主体）")
    void deviceIdMismatchRejected() {
        allowAll();
        when(deviceProofVerifier.verify(any(), any(), anyString(), any(), any())).thenReturn(evidence());
        when(principalRepository.findByHsmUid(UID))
                .thenReturn(Optional.of(principal(SecurityPrincipal.PrincipalState.ACTIVE)));
        when(mappingRepository.listActiveByPrincipalId(PRINCIPAL_ID)).thenReturn(List.of(mapping()));

        DeviceProofVerifyResultVo result = appService.verify(request(DeviceProofType.MTLS_CERT, "OTHER-SN"), "CIAM");

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.PROOF_INVALID.name(), result.getReasonCode());
    }
}
