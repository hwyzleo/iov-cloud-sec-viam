package net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * FW-SEC PkiClient 证书状态适配器（SEC-VIAM-DSN-CR-001 / D-VIAM-006 / FR-VIAM-004）
 * <p>
 * VIAM 准入仍适配 FW-SEC PkiClient；受信叶子证书/证据约束保持。
 * 任何无法获得确定 GOOD/REVOKED 的依赖结果一律抛异常（调用方 fail-closed），
 * 绝不返回 VALID 兜底；依赖故障不伪装为吊销。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateVerificationAdapter {

    private final ObjectProvider<PkiClient> pkiClientProvider;

    /**
     * 校验叶子证书状态。
     *
     * @param leafDerBase64 本次 mTLS 实际叶子证书 DER（Base64）
     * @param certSerial    证书序列号
     * @param certFingerprint 证书指纹
     * @param decisionAt    裁决时间
     * @return 验证结果
     * @throws ViamPkiDependencyUnavailable 依赖不可用/结果不确定（fail-closed）
     */
    public CertificateVerificationResult verify(String leafDerBase64, String certSerial, String certFingerprint,
                                                Instant decisionAt) {
        byte[] der = java.util.Base64.getDecoder().decode(leafDerBase64);
        if (der.length == 0 || der.length > 8 * 1024) {
            throw new ViamPkiDependencyUnavailable("叶子证书DER为空或超过8KiB上限");
        }
        PkiClient pkiClient = pkiClientProvider.getIfAvailable();
        if (pkiClient == null) {
            throw new ViamPkiDependencyUnavailable("framework PkiClient未装配");
        }
        try {
            PkiClient.CertificateStatusResult result = pkiClient.checkCertificateStatus(
                    new PkiClient.CertificateStatusQuery(der, certSerial, certFingerprint, decisionAt));
            CertificateStatus status = mapState(result.revocationState());
            if (status == CertificateStatus.UNKNOWN) {
                throw new ViamPkiDependencyUnavailable("PKI结果不确定（UNKNOWN），fail-closed");
            }
            return new CertificateVerificationResult(
                    status,
                    result.subjectCommonName(),
                    result.notBefore(),
                    result.notAfter(),
                    result.checkedAt() == null ? Instant.now() : result.checkedAt());
        } catch (CertificateStatusDependencyUnavailableException | CertificateStatusTrustValidationException
                 | CertificateStatusOutcomeUnknownException | CertificateStatusProtocolException
                 | CertificateStatusConfigurationException e) {
            throw new ViamPkiDependencyUnavailable(
                    "PKI证书状态查询失败: " + e.getClass().getSimpleName(), e);
        } catch (RuntimeException e) {
            throw new ViamPkiDependencyUnavailable("PKI证书状态查询异常: " + e.getClass().getSimpleName(), e);
        }
    }

    private static CertificateStatus mapState(PkiClient.RevocationState state) {
        if (state == null) {
            return CertificateStatus.UNKNOWN;
        }
        return switch (state) {
            case GOOD -> CertificateStatus.VALID;
            case REVOKED -> CertificateStatus.REVOKED;
            case UNKNOWN -> CertificateStatus.UNKNOWN;
        };
    }

    /**
     * 证书验证结果（不可变）。
     */
    public record CertificateVerificationResult(
            CertificateStatus status,
            String subjectCommonName,
            Instant notBefore,
            Instant notAfter,
            Instant checkedAt) {

        public long pkiLatencyMs() {
            return 0L;
        }
    }

    /**
     * 依赖不可用/结果不确定（fail-closed 信号）。
     */
    public static class ViamPkiDependencyUnavailable extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ViamPkiDependencyUnavailable(String message) {
            super(message);
        }

        public ViamPkiDependencyUnavailable(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
