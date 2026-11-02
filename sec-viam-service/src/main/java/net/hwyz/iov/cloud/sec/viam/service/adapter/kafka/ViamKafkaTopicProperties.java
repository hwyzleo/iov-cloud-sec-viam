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
