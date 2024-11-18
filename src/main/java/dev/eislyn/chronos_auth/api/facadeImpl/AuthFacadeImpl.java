package dev.eislyn.chronos_auth.api.facadeImpl;

import dev.eislyn.chronos_auth.api.annotation.MicroService;
import dev.eislyn.chronos_auth.api.facade.AuthFacade;
import dev.eislyn.chronos_auth.model.GenericResponse;
import dev.eislyn.chronos_auth.model.User;
import dev.eislyn.chronos_auth.producer.KafkaProducer;
import dev.eislyn.chronos_auth.service.IUserAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthFacadeImpl implements AuthFacade {
    private final IUserAuthService userAuthService;
    private final KafkaProducer kafkaProducer;

    @Override
    @MicroService
    public ResponseEntity<GenericResponse<User>> getCurrentUser() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = jwt.getClaimAsString("sub");
        User user = userAuthService.findUserByUsername(username);

        kafkaProducer.sendMessage(user.getId().toString());

        return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>("success", HttpStatus.OK, "Current logged in user retrieved successfully.", user));
    }
}
