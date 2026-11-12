package net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.SubjectRef;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * FW-SEC CertEnrollmentTemplate 证书注册适配器（SEC-VIAM-DSN-CR-001 / D-VIAM-006 / FR-VIAM-002）
 * <p>
 * 保留现行证书逻辑 Profile、CSR/leaf SPKI 及 CN 校验、用途/信任链/有效期/吊销与
 * 签发后 Profile 复验；结果未知（PkiOutcomeUnknown）转 PENDING_RECONCILE 禁止自动重签。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertEnrollmentAdapter {

    private final ObjectProvider<CertEnrollmentTemplate> templateProvider;

    /**
     * 提交证书申请（同步签发路径）。
     *
     * @param enrollment    证书记录（须已落库 REQUESTED）
     * @param csrDerBase64  CSR DER Base64
     */
    public void apply(CredentialEnrollment enrollment, String csrDerBase64) {
        CertEnrollmentTemplate template = requireTemplate();
        CertificateProfile profile = new CertificateProfile(
                enrollment.getCertificateProfile(),
                enrollment.getCertificateProfile(),
                CertificateProfile.SubjectType.DEVICE_IDENTITY,
                "ECDSA",
                "DIGITAL_SIGNATURE,KEY_AGREEMENT");
        CertApplyRequest request = new CertApplyRequest(
                profile,
                Base64.getDecoder().decode(csrDerBase64),
                new SubjectRef(SubjectRef.SubjectType.DEVICE_UID, enrollment.getHsmUid()),
                enrollment.getRequestId(),
                null);
        CertApplyResult result = template.apply(request);
        enrollment.setPkiRequestId(result.requestId());
        switch (result.state()) {
            case ISSUED -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUING);
                IssuedCertificate issued = template.getCertificate(result.requestId());
                if (issued != null) {
                    markIssuedFromTemplate(enrollment, issued);
                }
            }
            case REJECTED, FAILED -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.FAILED);
                enrollment.setFailReason("PKI拒绝或失败: " + result.state());
            }
            case UNKNOWN -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.PENDING_RECONCILE);
                enrollment.setFailReason("PKI结果未知: " + result.state());
            }
            default -> enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUING);
        }
    }

    /**
     * 按 PKI 申请编号重取已签发证书（SEC-VIAM-DSN-CR-002 / D-VIAM-015）。
     * <p>
     * 只读操作：仅用于管理面「获取证书本体」，不改状态、不落库、不缓存。
     * PKI 已不保留该申请材料时返回 null，由调用方给出明确失败，不伪造成功。
     * </p>
     *
     * @param pkiRequestId PKI 申请编号
     * @return 已签发证书（含叶子与链 DER），不可获取时为 null
     */
    public IssuedCertificate getCertificate(String pkiRequestId) {
        if (pkiRequestId == null || pkiRequestId.isBlank()) {
            return null;
        }
        return requireTemplate().getCertificate(pkiRequestId);
    }

    /**
     * 对账推进（getStatus/getCertificate）。
     */
    public void reconcile(CredentialEnrollment enrollment) {
        CertEnrollmentTemplate template = requireTemplate();
        CertApplyResult status = template.getStatus(enrollment.getPkiRequestId());
        switch (status.state()) {
            case ISSUED -> {
                IssuedCertificate issued = template.getCertificate(enrollment.getPkiRequestId());
                if (issued != null) {
                    markIssuedFromTemplate(enrollment, issued);
                }
            }
            case REJECTED, FAILED -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.FAILED);
                enrollment.setFailReason("PKI拒绝或失败: " + status.state());
            }
            case UNKNOWN -> {
                enrollment.setCertStatus(CredentialEnrollment.CertificateState.PENDING_RECONCILE);
                enrollment.setFailReason("PKI结果未知: " + status.state());
            }
            default -> enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUING);
        }
    }

    /**
     * 从模板 IssuedCertificate 登记证书元数据（签发后复验语义由模板校验保证）。
     */
    private void markIssuedFromTemplate(CredentialEnrollment enrollment, IssuedCertificate issued) {
        enrollment.setCertSn(net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.canonicalCertSn(issued.serialNumber()));
        enrollment.setCertificateFingerprint(issued.sha256Fingerprint());
        enrollment.setNotBefore(issued.notBefore());
        enrollment.setNotAfter(issued.notAfter());
        enrollment.setIssuedAt(java.time.Instant.now());
        enrollment.setCertStatus(CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED);
    }

    private CertEnrollmentTemplate requireTemplate() {
        return java.util.Optional.ofNullable(templateProvider.getIfAvailable())
                .orElseThrow(() -> new IllegalStateException("PKI证书注册模板未装配（PKI服务不可用）"));
    }
}
