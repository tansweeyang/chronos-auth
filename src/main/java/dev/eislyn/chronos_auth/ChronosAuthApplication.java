package dev.eislyn.chronos_auth;

import dev.eislyn.chronos_auth.config.RsaKeyProperties;
import dev.eislyn.chronos_auth.controller.AuthController;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;

@EnableDiscoveryClient
@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
@Import({AuthController.class})
public class ChronosAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ChronosAuthApplication.class, args);
    }

}
