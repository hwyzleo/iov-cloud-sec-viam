package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnlineEvidenceVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 成功接入证据门禁单元测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-005 / T01）
 * <p>
 * 普通 DEVICE_ONLINE 消息中 UID、VIN、generation 齐全，不自动等于已证明本次认证通过；
 * 缺少 admissionDecisionId/不可变准入快照等可信等效证据时，不写成功登录、不推进 ACTIVATING。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class SuccessfulDeviceLoginAppServiceTest {

    @InjectMocks
    private SuccessfulDeviceLoginAppService appService;

    private DeviceOnlineEvidenceVo evidenceWithoutDecisionId() {
        return DeviceOnlineEvidenceVo.builder()
                .eventId("EV-001")
                .eventType("DEVICE_ONLINE")
                .hsmUid("HSM-0001")
                .vin("VIN0000000000001")
                .sessionId("S1")
                .connectionGeneration(1)
                .certSerial("0a1b2c")
                .occurredAt(Instant.parse("2026-11-01T10:00:00Z"))
                .timeSource("EMQX")
                // 无 admissionDecisionId / admissionSnapshotDigest
                .build();
    }

    @Test
    void validateTrustedEvidence_rejectsFieldCompleteButNoDecisionId() {
        // UID/VIN/generation 齐全但无可信关联证据 → 拒绝
        SuccessfulDeviceLoginAppService.EvidenceCheck check =
                appService.validateTrustedEvidence(evidenceWithoutDecisionId());
        assertFalse(check.trusted());
        assertNotNull(check.reason());
    }

    @Test
    void validateTrustedEvidence_acceptsWithAdmissionDecisionId() {
        DeviceOnlineEvidenceVo evidence = evidenceWithoutDecisionId();
        evidence.setAdmissionDecisionId("ADM-001");
        SuccessfulDeviceLoginAppService.EvidenceCheck check =
                appService.validateTrustedEvidence(evidence);
        assertTrue(check.trusted());
    }

    @Test
    void validateTrustedEvidence_acceptsEquivalentSnapshot() {
        DeviceOnlineEvidenceVo evidence = evidenceWithoutDecisionId();
        evidence.setAdmissionSnapshotDigest("snap-digest");
        evidence.setAdmissionSnapshotExpiresAt(Instant.parse("2030-01-01T00:00:00Z"));
        SuccessfulDeviceLoginAppService.EvidenceCheck check =
                appService.validateTrustedEvidence(evidence);
        assertTrue(check.trusted());
    }

    @Test
    void validateTrustedEvidence_rejectsExpiredSnapshot() {
        DeviceOnlineEvidenceVo evidence = evidenceWithoutDecisionId();
        evidence.setAdmissionSnapshotDigest("snap-digest");
        evidence.setAdmissionSnapshotExpiresAt(Instant.parse("2020-01-01T00:00:00Z"));
        SuccessfulDeviceLoginAppService.EvidenceCheck check =
                appService.validateTrustedEvidence(evidence);
        assertFalse(check.trusted());
    }

    @Test
    void validateTrustedEvidence_rejectsMissingOccurredAt() {
        DeviceOnlineEvidenceVo evidence = evidenceWithoutDecisionId();
        evidence.setAdmissionDecisionId("ADM-001");
        evidence.setOccurredAt(null);
        SuccessfulDeviceLoginAppService.EvidenceCheck check =
                appService.validateTrustedEvidence(evidence);
        assertFalse(check.trusted());
    }
}
