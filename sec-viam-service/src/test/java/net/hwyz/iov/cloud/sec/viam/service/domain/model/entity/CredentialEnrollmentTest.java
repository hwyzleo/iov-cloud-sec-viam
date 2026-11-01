package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 证书登记状态机单元测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-002 / T03）
 * <p>
 * 覆盖：签发后复验登记、安装确认激活、终态不回退、结果未知转对账、重签作废。
 * </p>
 *
 * @author hwyz_leo
 */
class CredentialEnrollmentTest {

    private CredentialEnrollment newEnrollment() {
        return CredentialEnrollment.builder()
                .requestId("REQ-001")
                .vin("VIN0000000000001")
                .deviceSn("SN-0001")
                .hsmUid("HSM-0001")
                .certificateProfile("TBOX_DEVICE_ECDH_ES_P256_V1")
                .certStatus(CredentialEnrollment.CertificateState.REQUESTED)
                .build();
    }

    @Test
    void markIssued_registersMetadata() {
        CredentialEnrollment e = newEnrollment();
        e.markIssued("0a1b2c", "fp", "CN=HSM-0001", "CN=CA",
                Instant.parse("2026-11-01T00:00:00Z"), Instant.parse("2027-11-01T00:00:00Z"),
                new byte[]{1, 2, 3});
        assertEquals(CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED, e.getCertStatus());
        assertEquals("0a1b2c", e.getCertSn());
        assertTrue(e.isReusableStatus());
    }

    @Test
    void confirmInstalled_activatesAndTerminalNotReversed() {
        CredentialEnrollment e = newEnrollment();
        e.markIssued("0a1b2c", "fp", null, null, null, null, new byte[]{1});
        e.confirmInstalled();
        assertEquals(CredentialEnrollment.CertificateState.ACTIVE, e.getCertStatus());
        assertThrows(IllegalStateException.class, () -> e.markFailed("x")); // 终态不可回退为 FAILED
        assertThrows(IllegalStateException.class, e::confirmInstalled); // 重复确认
    }

    @Test
    void confirmInstallFailed_thenRetryConfirm() {
        CredentialEnrollment e = newEnrollment();
        e.markIssued("0a1b2c", "fp", null, null, null, null, new byte[]{1});
        e.confirmInstallFailed("安装校验失败");
        assertEquals(CredentialEnrollment.CertificateState.INSTALL_FAILED, e.getCertStatus());
        e.confirmInstalled(); // INSTALL_FAILED 可重试确认
        assertEquals(CredentialEnrollment.CertificateState.ACTIVE, e.getCertStatus());
    }

    @Test
    void markPendingReconcile_unknownOutcomeNoAutoReissue() {
        CredentialEnrollment e = newEnrollment();
        e.markPendingReconcile("PKI结果未知");
        assertEquals(CredentialEnrollment.CertificateState.PENDING_RECONCILE, e.getCertStatus());
    }

    @Test
    void supersedeForReissue_onlySettledStates() {
        CredentialEnrollment inFlight = newEnrollment();
        assertThrows(IllegalStateException.class, inFlight::supersedeForReissue); // REQUESTED 不可作废重签

        CredentialEnrollment settled = newEnrollment();
        settled.markIssued("0a1b2c", "fp", null, null, null, null, new byte[]{1});
        settled.confirmInstalled();
        settled.supersedeForReissue();
        assertEquals(CredentialEnrollment.CertificateState.SUPERSEDED, settled.getCertStatus());
    }
}
