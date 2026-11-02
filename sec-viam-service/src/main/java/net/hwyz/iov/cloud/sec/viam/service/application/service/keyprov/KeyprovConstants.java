package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * VIAM Keyprov 协议常量与枚举映射（迁入 VMD 既有实现，错误语义对齐 702xxx）。
 *
 * @author hwyz_leo
 */
public final class KeyprovConstants {

    private KeyprovConstants() {
    }

    public static final String BUSINESS_DOMAIN_V2C = "V2C_COMM";
    public static final String DERIVATION_VERSION_V1 = "v1";
    public static final String PURPOSE_UPLINK_AEAD = "UPLINK_AEAD";
    public static final String PURPOSE_DOWNLINK_AEAD = "DOWNLINK_AEAD";
    public static final List<String> V2C_PURPOSES = List.of(PURPOSE_UPLINK_AEAD, PURPOSE_DOWNLINK_AEAD);
    public static final Set<String> V2C_PURPOSE_SET = Set.copyOf(V2C_PURPOSES);

    public static final String SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM =
            "ECDH_ES_P256_HKDF_SHA256_AES256GCM";

    public static final String KEY_ALGORITHM_ECDH_ES_V1 = "AES-256";

    public static final String PAYLOAD_TYPE_REQUEST = "security.keyprov.v1.KeyProvisioningRequest";
    public static final String PAYLOAD_TYPE_RESPONSE = "security.keyprov.v1.KeyProvisioningResponse";
    public static final String PAYLOAD_TYPE_ACK = "security.keyprov.v1.KeyProvisioningAck";
    public static final String PAYLOAD_TYPE_ACK_RESULT = "security.keyprov.v1.KeyProvisioningAckResult";
    public static final String PAYLOAD_TYPE_STATUS_REQUEST = "security.keyprov.v1.KeyProvisioningStatusRequest";
    public static final String PAYLOAD_TYPE_STATUS_RESPONSE = "security.keyprov.v1.KeyProvisioningStatusResponse";
    public static final String ENVELOPE_SERVICE = "security.keyprov";
    public static final String PROTOCOL_VERSION = "keyprov-v1";

    /** 稳定协议错误（VAGW 映射 804010；不复制 702xxx 数字表） */
    public static final String ERR_NOT_FOUND = "KEYPROV_PROVISIONING_NOT_FOUND";
    public static final String ERR_PURPOSE_INCOMPLETE = "KEYPROV_PURPOSE_INCOMPLETE";
    public static final String ERR_ACK_CONFLICT = "KEYPROV_ACK_DIGEST_CONFLICT";
    public static final String ERR_STATE_NOT_ALLOWED = "KEYPROV_STATE_NOT_ALLOWED";
    public static final String ERR_ITEM_MISMATCH = "KEYPROV_ACK_ITEM_MISMATCH";
    public static final String ERR_DEVICE_NOT_ELIGIBLE = "KEYPROV_DEVICE_NOT_ELIGIBLE";
    public static final String ERR_CERTIFICATE_INVALID = "KEYPROV_CERTIFICATE_INVALID";
    public static final String ERR_EXPIRED = "KEYPROV_EXPIRED";
    public static final String ERR_PROTOCOL_INVALID = "KEYPROV_PROTOCOL_INVALID";
    public static final String ERR_UNAVAILABLE = "KEYPROV_VIAM_UNAVAILABLE";
    public static final String ERR_IDEMPOTENCY_CONFLICT = "KEYPROV_IDEMPOTENCY_CONFLICT";
    public static final String ERR_IMPORT_FAILED = "KEYPROV_IMPORT_FAILED";
    public static final String ERR_RECONCILE_REQUIRED = "KEYPROV_RECONCILE_REQUIRED";
    public static final String ERR_DERIVED_PROVIDER_NOT_READY = "KEYPROV_DERIVED_PROVIDER_NOT_READY";
    public static final String ERR_DERIVATION_UNSUPPORTED = "KEYPROV_DERIVATION_UNSUPPORTED";
    public static final String ERR_ENVELOPE_UNSUPPORTED = "KEYPROV_ENVELOPE_UNSUPPORTED";
    public static final String ERR_ENVELOPE_INTEGRITY = "KEYPROV_ENVELOPE_INTEGRITY";
    public static final String ERR_IMPORT_PROOF_INVALID = "KEYPROV_IMPORT_PROOF_INVALID";
    public static final String ERR_IMPORT_PROOF_NOT_READY = "KEYPROV_IMPORT_PROOF_NOT_READY";
    public static final String ERR_LOGICAL_KEY_IDENTITY_CONFLICT = "KEYPROV_LOGICAL_KEY_IDENTITY_CONFLICT";

    private static final Map<KeyPurpose, String> PURPOSE_TO_CODE = new LinkedHashMap<>();
    private static final Map<WrappingSuite, String> SUITE_TO_CODE = new LinkedHashMap<>();
    private static final Map<net.hwyz.iov.security.keyprov.v1.KeyPurpose, String> PROTO_PURPOSE_TO_CODE =
            new LinkedHashMap<>();
    private static final Map<String, net.hwyz.iov.security.keyprov.v1.KeyPurpose> CODE_TO_PROTO_PURPOSE =
            new LinkedHashMap<>();
    private static final Map<WrappingSuite, net.hwyz.iov.security.keyprov.v1.WrappingSuite> FRAMEWORK_SUITE_TO_PROTO =
            new LinkedHashMap<>();

    static {
        PURPOSE_TO_CODE.put(KeyPurpose.UPLINK_AEAD, PURPOSE_UPLINK_AEAD);
        PURPOSE_TO_CODE.put(KeyPurpose.DOWNLINK_AEAD, PURPOSE_DOWNLINK_AEAD);
        SUITE_TO_CODE.put(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        PROTO_PURPOSE_TO_CODE.put(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD,
                PURPOSE_UPLINK_AEAD);
        PROTO_PURPOSE_TO_CODE.put(net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD,
                PURPOSE_DOWNLINK_AEAD);
        CODE_TO_PROTO_PURPOSE.put(PURPOSE_UPLINK_AEAD,
                net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_UPLINK_AEAD);
        CODE_TO_PROTO_PURPOSE.put(PURPOSE_DOWNLINK_AEAD,
                net.hwyz.iov.security.keyprov.v1.KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD);
        FRAMEWORK_SUITE_TO_PROTO.put(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                net.hwyz.iov.security.keyprov.v1.WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
    }

    /** framework KeyPurpose → 目录用途代码 */
    public static String purposeCode(KeyPurpose purpose) {
        return PURPOSE_TO_CODE.get(purpose);
    }

    /** proto KeyPurpose → 目录用途代码 */
    public static String protoPurposeToCode(net.hwyz.iov.security.keyprov.v1.KeyPurpose purpose) {
        return PROTO_PURPOSE_TO_CODE.get(purpose);
    }

    /** 目录用途代码 → proto KeyPurpose */
    public static net.hwyz.iov.security.keyprov.v1.KeyPurpose codeToProtoPurpose(String code) {
        return CODE_TO_PROTO_PURPOSE.get(code);
    }

    /** framework WrappingSuite → 目录 suite 代码 */
    public static String suiteCode(WrappingSuite suite) {
        return SUITE_TO_CODE.get(suite);
    }

    /** framework WrappingSuite → proto WrappingSuite（PAR-PROTO 枚举） */
    public static net.hwyz.iov.security.keyprov.v1.WrappingSuite frameworkSuiteToProto(WrappingSuite suite) {
        return FRAMEWORK_SUITE_TO_PROTO.get(suite);
    }

    public static boolean isCompleteV2cPurposeSet(Set<String> purposes) {
        return purposes != null && purposes.equals(V2C_PURPOSE_SET);
    }

    public static boolean isSucceeded(KeyProvisioningResult result) {
        return result == KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED;
    }

    public static String importResultCode(KeyImportResult result) {
        return result == null ? null : result.name();
    }
}
