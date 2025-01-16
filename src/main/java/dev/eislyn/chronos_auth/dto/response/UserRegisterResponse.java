package dev.eislyn.chronos_auth.dto.response;

public record UserRegisterResponse(
        Long id,
        String email,
        String username,
        String roles,
        boolean enabled
) {
}
