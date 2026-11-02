package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofCapability;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 设备导入证明（ImportProof）真实验签校验（迁入 VMD/framework 既有能力）。
 * <p>
 * 使用 framework {@link net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier}
 * （ECDSA-P256）校验 ACK 中每个 item 的 importProof；设备叶子证书经
 * {@code crypto.pki.certificate-resolution} 解析并校验信任链/状态（fail-closed）。
 * 任何不确定/异常一律拒绝 ACK，不把校验失败伪装为成功。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ImportProofVerifier {

    private final net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier frameworkVerifier;

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
        if (!ImportProofCapability.supports(ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1)) {
            throw new ViamServiceException(ViamErrorCode.KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED,
                    "ImportProof 能力未装配（viam.crypto.import-proof.enabled=false）");
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
                    KeyPurpose.valueOf(purposeCode),
                    delivered.getKeyId(),
                    delivered.getBusinessKeyVersion(),
                    delivered.getEnvelopeDigest().toByteArray(),
                    delivered.getKeyCheckValue().toByteArray());
            VerifiedImportProof proof = frameworkVerifier.verify(req);
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
