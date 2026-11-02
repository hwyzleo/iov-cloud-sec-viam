package net.hwyz.iov.cloud.sec.viam.service.infrastructure.config;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.framework.kafka.topic.KafkaTopicDefinition;
import net.hwyz.iov.cloud.framework.kafka.topic.KafkaTopicDefinitionProvider;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.ViamKafkaTopicProperties;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

/**
 * VIAM Kafka Topic 定义提供者（SEC-VIAM-DSN-CR-001 §3）
 * <p>
 * 向 FW-KAFKA 声明 VIAM 作为生产者输出的 PRODUCER_OWNED Topic（待登记新契约，
 * schema/owner/ACL 登记后方可对外启用；本声明仅保证开发库建表就绪）：
 * <ul>
 *   <li>{@code viam.device.login-succeeded}：设备成功接入事件</li>
 *   <li>{@code viam.device.onboarding.changed}：安全开通状态变更事件</li>
 *   <li>{@code viam.device-certificate.changed}：设备证书变更事件</li>
 *   <li>{@code viam.business-key.changed}：业务密钥目录变更事件</li>
 *   <li>{@code viam.tbox-v2c-key-provisioned}：V2C 密钥开通完成事件</li>
 * </ul>
 * <p>
 * 不声明消费 Topic（vagw.device.online 由 VAGW 管理，VIAM 只消费不创建）。
 * Topic 名称统一来自 {@link ViamKafkaTopicProperties}，分区/副本/cleanup.policy
 * 通过 {@link ViamKafkaTopicProvisioningProperties} 环境参数注入。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
@RequiredArgsConstructor
public class ViamKafkaTopicDefinitionProvider implements KafkaTopicDefinitionProvider {

    private final ViamKafkaTopicProvisioningProperties provisioningProperties;
    private final ViamKafkaTopicProperties topicProperties;

    @Override
    public Collection<KafkaTopicDefinition> topicDefinitions() {
        return List.of(
                new KafkaTopicDefinition(topicProperties.getDeviceLoginSucceeded(),
                        provisioningProperties.getPartitions(), provisioningProperties.getReplicationFactor(),
                        provisioningProperties.configs()),
                new KafkaTopicDefinition(topicProperties.getDeviceOnboardingChanged(),
                        provisioningProperties.getPartitions(), provisioningProperties.getReplicationFactor(),
                        provisioningProperties.configs()),
                new KafkaTopicDefinition(topicProperties.getDeviceCertificateChanged(),
                        provisioningProperties.getPartitions(), provisioningProperties.getReplicationFactor(),
                        provisioningProperties.configs()),
                new KafkaTopicDefinition(topicProperties.getBusinessKeyChanged(),
                        provisioningProperties.getPartitions(), provisioningProperties.getReplicationFactor(),
                        provisioningProperties.configs()),
                new KafkaTopicDefinition(topicProperties.getTboxV2cKeyProvisioned(),
                        provisioningProperties.getPartitions(), provisioningProperties.getReplicationFactor(),
                        provisioningProperties.configs()),
                new KafkaTopicDefinition(topicProperties.getAccessInvalidated(),
                        provisioningProperties.getPartitions(), provisioningProperties.getReplicationFactor(),
                        provisioningProperties.configs()));
    }
}
