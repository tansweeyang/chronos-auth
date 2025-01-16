package dev.eislyn.chronos_auth.dto.response;

public record UserMeResponse(
        Long id,
        String email,
        String username,
        String roles,
        boolean enabled,
        String token
) {
}
