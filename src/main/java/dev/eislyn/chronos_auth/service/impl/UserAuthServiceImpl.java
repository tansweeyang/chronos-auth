package dev.eislyn.chronos_auth.service.impl;

import dev.eislyn.chronos_auth.api.converter.output.UserApiOutputConverter;
import dev.eislyn.chronos_auth.dto.request.RegisterRequestDto;
import dev.eislyn.chronos_auth.events.OnPasswordResetRequestEvent;
import dev.eislyn.chronos_auth.model.PasswordResetToken;
import dev.eislyn.chronos_auth.model.User;
import dev.eislyn.chronos_auth.model.VerificationToken;
import dev.eislyn.chronos_auth.repository.PasswordResetRepository;
import dev.eislyn.chronos_auth.repository.UserRepository;
import dev.eislyn.chronos_auth.repository.VerificationTokenRepository;
import dev.eislyn.chronos_auth.service.IUserAuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.rmi.NoSuchObjectException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserAuthServiceImpl implements IUserAuthService {
    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;
    private final PasswordResetRepository passwordResetRepository;
    private final UserApiOutputConverter userApiOutputConverter;

    @Override
    public User registerUser(RegisterRequestDto registerRequest) {
        // Check if password and confirmationPassword match
        if (!registerRequest.getPassword().equals(registerRequest.getConfirmationPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        // Check if username already exists
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already taken");
        }

        // Proceed with registration if validations pass
        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

        return userRepository.save(user);
    }

    @Override
    public User getUser(String verificationToken) {
        User user = userRepository.findByToken(verificationToken).get();
        return user;
    }

    @Override
    public void saveRegisteredUser(User user) {
        userRepository.save(user);
    }

    @Override
    public void createVerificationToken(User user, String token) {
        VerificationToken myToken = new VerificationToken(token, user);
        tokenRepository.save(myToken);
    }

    @Override
    public VerificationToken getVerificationToken(String VerificationToken) throws NoSuchObjectException {
        VerificationToken verificationToken = tokenRepository.findByToken(VerificationToken);
        if (verificationToken == null) {
            throw new NoSuchObjectException("Token is null.");
        }
        return verificationToken;
    }

    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElse(null);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElse((null));
    }

    public PasswordResetToken createPasswordResetTokenForUser(User user) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expiryDate = LocalDateTime.now().plusHours(24);
        PasswordResetToken passwordResetToken = new PasswordResetToken(token, user, expiryDate);
        return passwordResetRepository.save(passwordResetToken);
    }

    public void sendResetPasswordEmail(User user, HttpServletRequest request, String appUrl, String token) {
        eventPublisher.publishEvent(new OnPasswordResetRequestEvent(user, request.getLocale(), appUrl, token));
    }

    public String validatePasswordResetToken(String token) {
        final PasswordResetToken passToken = passwordResetRepository.findByToken(token);

        return !isTokenFound(passToken) ? "invalidToken"
                : isTokenExpired(passToken) ? "expired"
                : null;
    }

    private boolean isTokenFound(PasswordResetToken passToken) {
        return passToken != null;
    }

    public boolean isTokenExpired(PasswordResetToken passToken) {
        return LocalDateTime.now().isAfter(passToken.getExpiryDate());
    }

    public Optional<User> getUserByPasswordResetToken(String passToken) {
        // Find the PasswordResetToken by the token
        PasswordResetToken passwordResetToken = passwordResetRepository.findByToken(passToken);

        // If the token is found and not expired, return the associated user
        if (passwordResetToken != null && !isTokenExpired(passwordResetToken)) {
            return Optional.of(passwordResetToken.getUser());
        }

        // If the token is not found or is expired, return an empty Optional
        return Optional.empty();
    }

    public void changeUserPassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public void update(User user) {
        userRepository.save(user);
    }
}
