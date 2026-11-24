package net.hwyz.iov.cloud.sec.viam.service.adapter.kafka;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * VIAM Kafka Topic 属性（SEC-VIAM-DSN-CR-001）
 * <p>
 * 供 Listener SpEL 引用与 Producer/Outbox Relay 统一引用。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Component("viamKafkaTopicProperties")
public class ViamKafkaTopicProperties {

    @Value("${viam.kafka.topics.vagw-device-online:vagw.device.online}")
    private String vagwDeviceOnline;

    /**
     * VMD 车辆-零件绑定变更事件 topic（SEC-VIAM-DSN-CR-006 / D-VIAM-028）
     * <p>
     * 事件仅作触发信号：VIAM 收到后回查 VMD active 绑定快照收敛，不直接采信事件载荷完成身份登记。
     * </p>
     */
    @Value("${viam.kafka.topics.vmd-part-binding-changed:vmd.vehicle-part-binding.changed}")
    private String vmdPartBindingChanged;

    @Value("${viam.kafka.topics.device-login-succeeded:viam.device.login-succeeded}")
    private String deviceLoginSucceeded;

    @Value("${viam.kafka.topics.device-onboarding-changed:viam.device.onboarding.changed}")
    private String deviceOnboardingChanged;

    @Value("${viam.kafka.topics.device-certificate-changed:viam.device-certificate.changed}")
    private String deviceCertificateChanged;

    @Value("${viam.kafka.topics.business-key-changed:viam.business-key.changed}")
    private String businessKeyChanged;

    @Value("${viam.kafka.topics.tbox-v2c-key-provisioned:viam.tbox-v2c-key-provisioned}")
    private String tboxV2cKeyProvisioned;

    @Value("${viam.kafka.topics.access-invalidated:viam.access-invalidated}")
    private String accessInvalidated;
}
