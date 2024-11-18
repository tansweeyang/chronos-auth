package dev.eislyn.chronos_auth.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class kafkaTopicConfig {
    @Bean
    public NewTopic chronosAuthTopic() {
        return TopicBuilder
                .name("chronosAuthTopic")
                .build();
    }
}
