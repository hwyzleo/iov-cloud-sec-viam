package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofCapability;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 设备导入证明（ImportProof）真实验签校验（SEC-VIAM-DSN-CR-001 / G-2）。
 * <p>
 * 使用 framework {@link net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier}
 * （ECDSA-P256）校验 ACK 中每个 item 的 importProof；设备叶子证书经
 * {@code crypto.pki.certificate-resolution} 解析并校验信任链/状态（fail-closed）。
 * <p>
 * framework 验签器受 {@code crypto.import-proof.enabled} 条件门禁（默认 false）：
 * 本组件以 {@link ObjectProvider} 可选装配，能力未启用<b>不阻断应用启动</b>；
 * ACK 验签时能力缺失 → KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED（fail-closed），
 * 与 Keyprov 整体为门禁能力（{@code viam.crypto.provisioning.enabled=false} → UNAVAILABLE）一致。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ImportProofVerifier {

    private final ObjectProvider<net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier> verifierProvider;

    public ImportProofVerifier(
            ObjectProvider<net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier> verifierProvider) {
        this.verifierProvider = verifierProvider;
    }

    /**
     * 校验 ACK 全部 item 的导入证明。
     *
     * @param items              ACK 携带的 item 结果（purpose → item）
     * @param deliveredByPurpose 冻结响应中已交付的 canonical item（含 envelopeDigest/KCV）
     * @param requestId          批次 requestId
     * @param businessDomain     业务域（V2C_COMM）
     * @param certificate        设备叶子证书登记（受信来源）
     * @return 校验通过的 proof 摘要（逐 item）
     */
    public Map<String, VerifiedImportProof> verifyAll(List<KeyImportItemResult> items,
                                                      Map<String, WrappedKeyItem> deliveredByPurpose,
                                                      String requestId, String businessDomain,
                                                      CredentialEnrollment certificate) {
        if (certificate == null || certificate.getCertSn() == null) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED,
                    "设备叶子证书登记缺失，无法验签");
        }
        net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier verifier = verifierProvider.getIfAvailable();
        if (verifier == null || !ImportProofCapability.supports(ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1)) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED,
                    "ImportProof 能力未装配（viam.crypto.import-proof.enabled=false），ACK 验签 fail-closed");
        }
        DeviceCertificateRef certRef = DeviceCertificateRef.ofSerial(certificate.getCertSn());
        byte[] expectedCertDigest = certificate.getLeafCertificateDigest();
        java.util.LinkedHashMap<String, VerifiedImportProof> verified = new java.util.LinkedHashMap<>();
        for (KeyImportItemResult item : items) {
            String purposeCode = protoPurposeToCode(item.getPurpose().name());
            WrappedKeyItem delivered = deliveredByPurpose.get(purposeCode);
            if (delivered == null) {
                throw new ViamServiceException(ViamErrorCode.KEYPROV_ITEM_MISMATCH,
                        "ACK item 无对应已交付 canonical item: purpose=" + purposeCode);
            }
            if (item.getImportProof() == null || item.getImportProof().isEmpty()) {
                throw new ViamServiceException(ViamErrorCode.KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED,
                        "ACK item 缺少 importProof: purpose=" + purposeCode);
            }
            ImportProofVerificationRequest req = new ImportProofVerificationRequest(
                    ImportProofAlgorithm.ECDSA_P256_SHA256_P1363,
                    item.getImportProof().toByteArray(),
                    certRef,
                    expectedCertDigest,
                    requestId,
                    businessDomain,
                    net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose.valueOf(purposeCode),
                    delivered.getKeyId(),
                    delivered.getBusinessKeyVersion(),
                    delivered.getEnvelopeDigest().toByteArray(),
                    delivered.getKeyCheckValue().toByteArray());
            VerifiedImportProof proof = verifier.verify(req);
            verified.put(purposeCode, proof);
        }
        return verified;
    }

    private static String protoPurposeToCode(String protoName) {
        if (protoName == null) {
            return null;
        }
        if (protoName.startsWith("KEY_PURPOSE_")) {
            return protoName.substring("KEY_PURPOSE_".length());
        }
        return protoName;
    }
}
