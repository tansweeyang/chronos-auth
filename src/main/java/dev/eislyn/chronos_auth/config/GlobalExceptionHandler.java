package dev.eislyn.chronos_auth.config;

import dev.eislyn.chronos_auth.exceptions.UserVerifiedException;
import dev.eislyn.chronos_auth.model.GenericResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.rmi.NoSuchObjectException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MailException.class)
    public ResponseEntity<GenericResponse<String>> handleMailException(MailException e) {
        log.error("MailException: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new GenericResponse<>("Error", HttpStatus.INTERNAL_SERVER_ERROR.value(), "User registered successfully, but the verification email could not be sent: " + e.getMessage(), null));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<GenericResponse<String>> handleIllegalArgumentException(IllegalArgumentException e) {
        log.error("IllegalArgumentException: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new GenericResponse<>("Error", HttpStatus.BAD_REQUEST.value(), "Registration failed: " + e.getMessage(), null));
    }

    @ExceptionHandler(NoSuchObjectException.class)
    public ResponseEntity<GenericResponse<String>> handleNoSuchObjectException(NoSuchObjectException e) {
        log.error("NoSuchObjectException: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new GenericResponse<>("Error", HttpStatus.NOT_FOUND.value(), "Invalid or expired token. Please request again.", null));
    }

    @ExceptionHandler(UserVerifiedException.class)
    public ResponseEntity<GenericResponse<String>> handleUserVerifiedException(UserVerifiedException e) {
        log.error("UserVerifiedException: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new GenericResponse<>("Error", HttpStatus.FORBIDDEN.value(), "User is already verified.", null));
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<GenericResponse<String>> handleUsernameNotFoundException(UsernameNotFoundException e) {
        log.error("UsernameNotFoundException: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new GenericResponse<>("Error", HttpStatus.BAD_REQUEST.value(), "Login failed: Wrong username or password. Please try again.", null));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<GenericResponse<String>> handleBadCredentialsException(BadCredentialsException e) {
        log.error("BadCredentialsException: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new GenericResponse<>("Error", HttpStatus.FORBIDDEN.value(), "Login failed: Wrong username or password. Please try again.", null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<GenericResponse<String>> handleGenericException(Exception e) {
        log.error("Exception: {}", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new GenericResponse<>("Error", HttpStatus.INTERNAL_SERVER_ERROR.value(), "An unexpected error occurred. Please try again later.", null));
    }
}
