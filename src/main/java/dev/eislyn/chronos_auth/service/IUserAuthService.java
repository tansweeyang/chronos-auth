package dev.eislyn.chronos_auth.service;

import dev.eislyn.chronos_auth.dto.request.RegisterRequestDto;
import dev.eislyn.chronos_auth.model.PasswordResetToken;
import dev.eislyn.chronos_auth.model.User;
import dev.eislyn.chronos_auth.model.VerificationToken;
import jakarta.servlet.http.HttpServletRequest;

import java.rmi.NoSuchObjectException;
import java.util.Optional;

public interface IUserAuthService {
    // Register
    User registerUser(RegisterRequestDto userDto);
    User getUser(String verificationToken);
    void saveRegisteredUser(User user);
    void createVerificationToken(User user, String token);
    VerificationToken getVerificationToken(String VerificationToken) throws NoSuchObjectException;

    // Reset password
    User findUserByEmail(String email);
    User findUserByUsername(String username);
    PasswordResetToken createPasswordResetTokenForUser(User user);
    void sendResetPasswordEmail(User user, HttpServletRequest request, String appUrl, String token);
    String validatePasswordResetToken(String token);
    Optional<User> getUserByPasswordResetToken(String passToken);
    void changeUserPassword (User user, String newPassword);
}
