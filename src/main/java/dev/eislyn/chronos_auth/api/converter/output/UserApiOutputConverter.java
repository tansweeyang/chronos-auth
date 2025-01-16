package dev.eislyn.chronos_auth.api.converter.output;

import dev.eislyn.chronos_auth.dto.response.UserMeResponse;
import dev.eislyn.chronos_auth.dto.response.UserRegisterResponse;
import dev.eislyn.chronos_auth.model.User;
import org.mapstruct.Mapper;
import org.springframework.stereotype.Component;

@Component
@Mapper(componentModel = "spring", implementationName = "UserApiOutputConverterImpl")
public interface UserApiOutputConverter {
    UserMeResponse user2UserResponseDto(User user);

    UserRegisterResponse user2UserRegisterResponseDto(User registeredUser);
}
