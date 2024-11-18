package dev.eislyn.chronos_auth.api.facade;

import dev.eislyn.chronos_auth.model.GenericResponse;
import dev.eislyn.chronos_auth.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public interface AuthFacade {
    ResponseEntity<GenericResponse<User>> getCurrentUser();
}
