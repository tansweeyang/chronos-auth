package dev.eislyn.chronos_auth.dto.response;

public record UserMeResponseDto(
        Long id,
        String email,
        String username,
        String roles,
        boolean enabled,
        String token
) {
}
