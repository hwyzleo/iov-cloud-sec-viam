package net.hwyz.iov.cloud.sec.viam.api.constant;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * VIAM 旧错误码 → 新 702xxx 映射层（SEC-VIAM-DSN-CR-001 §3）
 * <p>
 * 旧 806xxx（VMD）/ 401xxx（TSP）源码错误在单一分类层映射到 VIAM 新码；
 * VAGW 继续输出自身 804xxx，不纳入本映射。旧错误号退役不复用。
 * </p>
 *
 * @author hwyz_leo
 */
public final class ViamLegacyCodeMapping {

    private static final Map<String, String> LEGACY_TO_NEW = new HashMap<>();

    static {
        // ================= VMD 806xxx（证书/业务密钥/Keyprov） =================
        LEGACY_TO_NEW.put("806040", "702201"); // CERTIFICATE_VIN_NOT_EXIST
        LEGACY_TO_NEW.put("806041", "702202"); // CERTIFICATE_DEVICE_NOT_BOUND
        LEGACY_TO_NEW.put("806042", "702203"); // CERTIFICATE_DEVICE_CATEGORY_MISMATCH
        LEGACY_TO_NEW.put("806043", "702204"); // CERTIFICATE_CSR_INVALID
        LEGACY_TO_NEW.put("806044", "702205"); // CERTIFICATE_CSR_SUBJECT_MISMATCH
        LEGACY_TO_NEW.put("806045", "702206"); // CERTIFICATE_CSR_CONTAINS_VIN
        LEGACY_TO_NEW.put("806046", "702207"); // CERTIFICATE_PROFILE_NOT_ALLOWED
        LEGACY_TO_NEW.put("806047", "702208"); // CERTIFICATE_PKI_UNAVAILABLE
        LEGACY_TO_NEW.put("806048", "702209"); // CERTIFICATE_ISSUANCE_UNKNOWN
        LEGACY_TO_NEW.put("806049", "702210"); // CERTIFICATE_PKI_REJECTED
        LEGACY_TO_NEW.put("806050", "702211"); // CERTIFICATE_INSTALL_CONFIRM_MISMATCH
        LEGACY_TO_NEW.put("806051", "702212"); // CERTIFICATE_STATUS_NOT_ALLOWED
        LEGACY_TO_NEW.put("806052", "702213"); // CERTIFICATE_REQUEST_NOT_EXIST
        LEGACY_TO_NEW.put("806060", "702214"); // CERTIFICATE_COMPENSATION_NOT_ALLOWED
        LEGACY_TO_NEW.put("806061", "702215"); // CERTIFICATE_REQUEST_IDEMPOTENCY_CONFLICT
        LEGACY_TO_NEW.put("806064", "702216"); // CERTIFICATE_KEY_CONFLICT
        LEGACY_TO_NEW.put("806065", "702002"); // CERTIFICATE_DEVICE_UID_UNAVAILABLE

        LEGACY_TO_NEW.put("806066", "702301"); // BUSINESS_KEY_DEVICE_SESSION_MISMATCH
        LEGACY_TO_NEW.put("806067", "702302"); // BUSINESS_KEY_DOMAIN_NOT_AUTHORIZED
        LEGACY_TO_NEW.put("806068", "702303"); // BUSINESS_KEY_NOT_EXIST
        LEGACY_TO_NEW.put("806069", "702304"); // BUSINESS_KEY_MULTIPLE_ACTIVE
        LEGACY_TO_NEW.put("806070", "702305"); // BUSINESS_KEY_STATE_NOT_ALLOWED
        LEGACY_TO_NEW.put("806071", "702306"); // BUSINESS_KEY_IDEMPOTENCY_CONFLICT
        LEGACY_TO_NEW.put("806072", "702307"); // BUSINESS_KEY_ROTATION_CONFLICT
        LEGACY_TO_NEW.put("806073", "702308"); // BUSINESS_KEY_DEVICE_CERT_NOT_FOUND
        LEGACY_TO_NEW.put("806074", "702309"); // BUSINESS_KEY_KMS_UNAVAILABLE
        LEGACY_TO_NEW.put("806075", "702310"); // BUSINESS_KEY_WRAP_FAILED
        LEGACY_TO_NEW.put("806076", "702311"); // BUSINESS_KEY_REVOCATION_FAILED
        LEGACY_TO_NEW.put("806077", "702312"); // BUSINESS_KEY_OUTCOME_UNKNOWN

        LEGACY_TO_NEW.put("806083", "702403"); // BUSINESS_KEY_PROVISIONING_NOT_FOUND
        LEGACY_TO_NEW.put("806084", "702404"); // BUSINESS_KEY_PROVISIONING_PURPOSE_INCOMPLETE
        LEGACY_TO_NEW.put("806085", "702405"); // BUSINESS_KEY_PROVISIONING_ACK_CONFLICT
        LEGACY_TO_NEW.put("806086", "702406"); // BUSINESS_KEY_PROVISIONING_STATE_NOT_ALLOWED
        LEGACY_TO_NEW.put("806087", "702407"); // BUSINESS_KEY_PROVISIONING_ITEM_MISMATCH
        LEGACY_TO_NEW.put("806088", "702408"); // BUSINESS_KEY_PROVISIONING_DEVICE_NOT_ELIGIBLE
        LEGACY_TO_NEW.put("806089", "702409"); // BUSINESS_KEY_PROVISIONING_EXPIRED

        // ================= TSP 401xxx（准入） =================
        LEGACY_TO_NEW.put("401001", "702101"); // UID_UNKNOWN
        LEGACY_TO_NEW.put("401016", "702102"); // IDENTITY_MISMATCH
        LEGACY_TO_NEW.put("401002", "702103"); // UNBOUND
        LEGACY_TO_NEW.put("401003", "702104"); // BINDING_CONFLICT
        LEGACY_TO_NEW.put("401004", "702105"); // CERT_REVOKED
        LEGACY_TO_NEW.put("401005", "702106"); // CERT_EXPIRED
        LEGACY_TO_NEW.put("401006", "702107"); // DEVICE_BLOCKED
        LEGACY_TO_NEW.put("401007", "702108"); // DEVICE_RETIRED
        LEGACY_TO_NEW.put("401008", "702109"); // DEPENDENCY_UNAVAILABLE
    }

    private ViamLegacyCodeMapping() {
    }

    /**
     * 映射旧源码错误码到新 702xxx 码；未登记返回 empty。
     */
    public static Optional<String> mapLegacy(String legacyCode) {
        if (legacyCode == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(LEGACY_TO_NEW.get(legacyCode));
    }

    /**
     * 新码（存在时）或原码。
     */
    public static String mapOrSelf(String legacyCode) {
        return mapLegacy(legacyCode).orElse(legacyCode);
    }
}
