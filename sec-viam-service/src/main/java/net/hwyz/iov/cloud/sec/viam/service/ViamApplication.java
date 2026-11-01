package net.hwyz.iov.cloud.sec.viam.service;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.annotation.EnableCustomConfig;
import net.hwyz.iov.cloud.framework.security.annotation.EnableCustomFeignClients;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * VIAM 启动类（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Slf4j
@EnableAsync
@EnableCustomConfig
@EnableDiscoveryClient
@EnableCustomFeignClients
@SpringBootApplication
public class ViamApplication {

    public static void main(String[] args) {
        SpringApplication.run(ViamApplication.class, args);
        log.info("应用启动完成");
    }
}
