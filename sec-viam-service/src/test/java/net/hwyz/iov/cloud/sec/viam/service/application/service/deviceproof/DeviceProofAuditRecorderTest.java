package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

/**
 * 设备证明校验审计记录器单元测试（SEC-VIAM-DSN-CR-003 / TC-VIAM-3-05）。
 * <p>
 * 断言：复用既有审计载体、只落摘要与结论、不落证明/证书原文与完整 deviceId。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DeviceProofAuditRecorderTest {

    private static final String PROOF = "AQIDBAUGBwgJCg==";
    private static final String NONCE = "nonce-0123456789abcdef";
    private static final String DEVICE_ID = "SN-SECRET-0001";

    @Mock
    private SecurityOperationAuditRepository auditRepository;

    private DeviceProofAuditRecorder recorder;

    @BeforeEach
    void setUp() {
        recorder = new DeviceProofAuditRecorder(auditRepository, new ObjectMapper());
    }

    @Test
    @DisplayName("审计只含摘要/结论/耗时，不含证明、nonce 原文与完整 deviceId")
    void auditContainsDigestsOnly() {
        recorder.record("DP-1", "CIAM", "PR-001", "MTLS_CERT", "proof-digest", "nonce-digest", DEVICE_ID,
                "PROOF_VALID", null, 12L, Instant.parse("2026-11-20T10:00:00Z"));

        ArgumentCaptor<SecurityOperationAudit> captor = ArgumentCaptor.forClass(SecurityOperationAudit.class);
        verify(auditRepository).save(captor.capture());
        SecurityOperationAudit audit = captor.getValue();

        assertEquals("DP-1", audit.getOperationId());
        assertEquals(DeviceProofAuditRecorder.OPERATION, audit.getOperation());
        assertEquals("PROOF_VALID", audit.getReason());
        assertEquals("CIAM", audit.getCallerType());
        assertEquals("PR-001", audit.getPrincipalId());
        assertTrue(audit.getDetail().contains("\"proofDigest\":\"proof-digest\""));
        assertTrue(audit.getDetail().contains("\"nonceDigest\":\"nonce-digest\""));
        assertTrue(audit.getDetail().contains("\"elapsedMs\":12"));
        assertFalse(audit.getDetail().contains(PROOF));
        assertFalse(audit.getDetail().contains(NONCE));
        assertFalse(audit.getDetail().contains(DEVICE_ID));
        // 审计不落 hsmUid/VIN/设备SN 明文
        assertEquals(null, audit.getHsmUid());
        assertEquals(null, audit.getVin());
        assertEquals(null, audit.getDeviceSn());
    }

    @Test
    @DisplayName("审计写入失败不抛出（不改变已得结论）")
    void auditFailureDoesNotThrow() {
        doThrow(new IllegalStateException("db down")).when(auditRepository).save(any());

        recorder.record("DP-2", "CIAM", null, "MTLS_CERT", "d", "d", DEVICE_ID,
                "DEPENDENCY_UNAVAILABLE", "702724", 5L, Instant.now());
        // 无异常即通过
    }

    @Test
    @DisplayName("未定位主体时使用占位主体ID（列 NOT NULL），detail 不超过 512")
    void unknownPrincipalUsesPlaceholder() {
        recorder.record("DP-3", "CIAM", null, "MTLS_CERT", "d", "d", DEVICE_ID,
                "PROOF_INVALID", "702721", 5L, Instant.now());

        ArgumentCaptor<SecurityOperationAudit> captor = ArgumentCaptor.forClass(SecurityOperationAudit.class);
        verify(auditRepository).save(captor.capture());
        assertEquals(DeviceProofAuditRecorder.PLACEHOLDER_PRINCIPAL, captor.getValue().getPrincipalId());
        assertTrue(captor.getValue().getDetail().length() <= 512);
    }
}
