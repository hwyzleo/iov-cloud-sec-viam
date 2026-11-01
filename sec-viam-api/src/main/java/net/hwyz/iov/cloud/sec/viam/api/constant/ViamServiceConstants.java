package net.hwyz.iov.cloud.sec.viam.api.constant;

/**
 * VIAM 服务名与路径常量（SEC-VIAM-DSN-CR-001）
 * <p>
 * 服务发现名称 {@code sec-viam} 已登记于 framework-common {@code ServiceNameConstants.SEC_VIAM}，
 * 本处不复制第二套服务名常量，仅承载 VIAM 内部契约路径。
 * </p>
 *
 * @author hwyz_leo
 */
public final class ViamServiceConstants {

    private ViamServiceConstants() {
    }

    /** 官方服务基础路径（Feign 契约统一引用） */
    public static final String SERVICE_BASE = "/api/service";

    /** 设备接入准入裁决 */
    public static final String DEVICE_ADMISSION_V1 = SERVICE_BASE + "/deviceAdmission/v1";

    /** 车辆接入身份反查 */
    public static final String VEHICLE_ACCESS_IDENTITY_V1 = SERVICE_BASE + "/vehicleAccessIdentity/v1";

    /** 设备证书生命周期 */
    public static final String VEHICLE_CERTIFICATE_V1 = SERVICE_BASE + "/vehicleCertificate/v1";

    /** 业务密钥目录 */
    public static final String BUSINESS_KEY_V1 = SERVICE_BASE + "/businessKey/v1";

    /** Keyprov 官方服务 */
    public static final String KEY_PROVISIONING_V1 = SERVICE_BASE + "/keyProvisioning/v1";

    /** 安全开通状态（onboarding） */
    public static final String DEVICE_ONBOARDING_V1 = SERVICE_BASE + "/deviceOnboarding/v1";

    /** 成功接入记录（登录时间线） */
    public static final String DEVICE_LOGIN_V1 = SERVICE_BASE + "/deviceLogin/v1";
}
