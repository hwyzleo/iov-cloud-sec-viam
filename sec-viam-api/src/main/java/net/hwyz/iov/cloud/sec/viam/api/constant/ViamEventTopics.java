package net.hwyz.iov.cloud.sec.viam.api.constant;

/**
 * VIAM 事件 Topic 契约（SEC-VIAM-DSN-CR-001 §3/§6）
 * <p>
 * 以下为待登记的新契约 Topic（schema/producer owner/key/consumer/group/ACL 登记后方可启用），
 * 不是已存在 Topic。旧 vmd.* Outbox 仅由迁移记录指定的单一 drain owner 原样排空，
 * 不得 VMD 与 VIAM 双发。
 * </p>
 *
 * @author hwyz_leo
 */
public final class ViamEventTopics {

    private ViamEventTopics() {
    }

    /** 设备成功接入事件（key=principalId 或稳定 hsmUid，二选一在 schema 登记时固定） */
    public static final String DEVICE_LOGIN_SUCCEEDED = "viam.device.login-succeeded";

    /** 安全开通状态变更事件 */
    public static final String DEVICE_ONBOARDING_CHANGED = "viam.device.onboarding.changed";

    /** 设备证书变更事件 */
    public static final String DEVICE_CERTIFICATE_CHANGED = "viam.device-certificate.changed";

    /** 业务密钥目录变更事件 */
    public static final String BUSINESS_KEY_CHANGED = "viam.business-key.changed";

    /** V2C 密钥开通完成事件（key 继续 deviceSn；完整用途集聚合事件） */
    public static final String TBOX_V2C_KEY_PROVISIONED = "viam.tbox-v2c-key-provisioned";

    /** 消费端：VAGW 设备上线事件（输入，EDD-VAGW-DSN-CR-012） */
    public static final String VAGW_DEVICE_ONLINE = "vagw.device.online";
}
