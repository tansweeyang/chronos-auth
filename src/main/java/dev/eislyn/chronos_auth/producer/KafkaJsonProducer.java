package dev.eislyn.chronos_auth.producer;

import dev.eislyn.chronos_auth.dto.response.UserMeResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class KafkaJsonProducer {
    private final KafkaTemplate<String, UserMeResponseDto> kafkaTemplate;

    public void sendMessage(UserMeResponseDto user) {
        Message<UserMeResponseDto> message = MessageBuilder
                .withPayload(user)
                .setHeader(KafkaHeaders.TOPIC, "chronosAuthTopic")
                .build();

        kafkaTemplate.send(message);
    }
}
