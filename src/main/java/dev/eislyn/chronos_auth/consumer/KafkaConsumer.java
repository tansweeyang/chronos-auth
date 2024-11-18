package dev.eislyn.chronos_auth.consumer;

import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class KafkaConsumer {
    @KafkaListener(topics = "chronosAuthTopic", groupId = "myGroup")
    public void consumeMessage(String message) {
        log.info(String.format("Consuming the message from chronosAuthTopic:: %s", message));
    }
}
