package dev.eislyn.chronos_auth.controller;

import dev.eislyn.chronos_auth.api.converter.output.UserApiOutputConverter;
import dev.eislyn.chronos_auth.dto.request.LoginRequestDto;
import dev.eislyn.chronos_auth.dto.request.PasswordDto;
import dev.eislyn.chronos_auth.dto.request.RegisterRequestDto;
import dev.eislyn.chronos_auth.dto.response.UserMeResponseDto;
import dev.eislyn.chronos_auth.events.OnRegistrationCompleteEvent;
import dev.eislyn.chronos_auth.exceptions.UserVerifiedException;
import dev.eislyn.chronos_auth.model.GenericResponse;
import dev.eislyn.chronos_auth.model.PasswordResetToken;
import dev.eislyn.chronos_auth.model.User;
import dev.eislyn.chronos_auth.model.VerificationToken;
import dev.eislyn.chronos_auth.producer.KafkaJsonProducer;
import dev.eislyn.chronos_auth.service.IUserAuthService;
import dev.eislyn.chronos_auth.service.impl.TokenServiceImpl;
import dev.eislyn.chronos_auth.service.impl.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;

import java.rmi.NoSuchObjectException;
import java.util.Locale;
import java.util.Optional;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final TokenServiceImpl tokenService;
    private final AuthenticationManager authenticationManager;
    private final ApplicationEventPublisher eventPublisher;
    private final UserDetailsServiceImpl userDetailsService;
    private final IUserAuthService userAuthService;
    private final UserApiOutputConverter userApiOutputConverter;
    private final KafkaJsonProducer kafkaJsonProducer;

    @Value("${APP_URL}")
    private String appUrl;

    @PostMapping("/register")
    public ResponseEntity<GenericResponse<UserMeResponseDto>> register(HttpServletRequest request, @Valid @RequestBody RegisterRequestDto registerRequest) {
        try {
            User registeredUser = userAuthService.registerUser(registerRequest);
            UserMeResponseDto responseDto = userApiOutputConverter.user2UserResponseDto(registeredUser);
            eventPublisher.publishEvent(new OnRegistrationCompleteEvent(registeredUser, request.getLocale(), appUrl));
            return ResponseEntity.status(HttpStatus.CREATED).body(new GenericResponse<>("success", HttpStatus.CREATED, "User registered successfully. Verification email is sent successfully.", responseDto));
        } catch (MailException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new GenericResponse<>("error", HttpStatus.INTERNAL_SERVER_ERROR, "User registered successfully, but the verification email could not be sent: " + e.getMessage(), null));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>("error", HttpStatus.BAD_REQUEST, "Registration failed: " + e.getMessage(), null));
        } catch (Exception e) {
            log.info("Unexpected error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new GenericResponse<>("error", HttpStatus.INTERNAL_SERVER_ERROR, "Registration failed: An unexpected error occurred. Please try again later.", null));
        }
    }

    @GetMapping("/registrationConfirm")
    public ResponseEntity<GenericResponse<String>> confirmRegistration(WebRequest request, @RequestParam("token") String token) {
        try {
            VerificationToken verificationToken = userAuthService.getVerificationToken(token);
            User user = verificationToken.getUser();
            user.setEnabled(true);
            userAuthService.saveRegisteredUser(user);
            return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>("success", HttpStatus.OK, "Email verified successfully.", null));
        } catch (NoSuchObjectException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new GenericResponse<>("error", HttpStatus.NOT_FOUND, "Invalid or expired token. Please request again.", null));
        } catch (UserVerifiedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new GenericResponse<>("error", HttpStatus.FORBIDDEN, "User is already verified.", null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new GenericResponse<>("error", HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.", null));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<GenericResponse<String>> login(@Valid @RequestBody LoginRequestDto loginRequest) {
        log.info("user is enabled", userDetailsService.loadUserByUsername(loginRequest.getUsername()).isEnabled());

        if (!userDetailsService.loadUserByUsername(loginRequest.getUsername()).isEnabled()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new GenericResponse<>("error", HttpStatus.FORBIDDEN, "Login denied. Please confirm your email.", null));
        }
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            String token = tokenService.generateToken(authentication);
            return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>("success", HttpStatus.OK, "Login successful", token));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>("error", HttpStatus.UNAUTHORIZED, "Login failed: Wrong username or password. Please try again.", null));
        }
    }

    @PostMapping("/resetPassword")
    public ResponseEntity<GenericResponse<String>> resetPassword(HttpServletRequest request, @RequestParam("email") String userEmail) {
        User user = userAuthService.findUserByEmail(userEmail);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new GenericResponse<>("error", HttpStatus.NOT_FOUND, "User not found, please register.", null));
        }
        PasswordResetToken token = userAuthService.createPasswordResetTokenForUser(user);
        userAuthService.sendResetPasswordEmail(user, request, appUrl, token.getToken());

        return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>("success", HttpStatus.OK, "Password reset email sent successfully", null));
    }

    @PostMapping("/savePassword")
    public ResponseEntity<GenericResponse<String>> savePassword(@Valid @RequestBody PasswordDto passwordDto) {
        if (!passwordDto.getNewPassword().equals(passwordDto.getConfirmationPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>("error", HttpStatus.BAD_REQUEST, "Password and confirm password do not match.", null));
        }

        String result = userAuthService.validatePasswordResetToken(passwordDto.getToken());

        if (result != null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new GenericResponse<>("error", HttpStatus.FORBIDDEN, "Reset password token is invalid or expired. Please request again.", null));
        }

        Optional<User> user = userAuthService.getUserByPasswordResetToken(passwordDto.getToken());
        if (user.isPresent()) {
            userAuthService.changeUserPassword(user.get(), passwordDto.getNewPassword());
            return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>("success", HttpStatus.OK, "Password is reset successfully", null));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new GenericResponse<>("error", HttpStatus.NOT_FOUND, "User cannot be found, please register.", null));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<GenericResponse<UserMeResponseDto>> getCurrentUser() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = jwt.getClaimAsString("sub");
        User user = userAuthService.findByUsername(username);

        UserMeResponseDto response = userApiOutputConverter.user2UserResponseDto(user);

        kafkaJsonProducer.sendMessage(response);

        return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>("success", HttpStatus.OK, "Current logged in user retrieved successfully.", response));
    }
}