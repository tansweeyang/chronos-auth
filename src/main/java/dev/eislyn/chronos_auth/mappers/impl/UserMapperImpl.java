package dev.eislyn.chronos_auth.mappers.impl;

import dev.eislyn.chronos_auth.dto.response.UserMeResponseDto;
import dev.eislyn.chronos_auth.mappers.Mapper;
import dev.eislyn.chronos_auth.model.User;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
public class UserMapperImpl implements Mapper<User, UserMeResponseDto> {
    private ModelMapper modelMapper;

    public UserMapperImpl(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }

    @Override
    public UserMeResponseDto mapTo(User user) {
        return modelMapper.map(user, UserMeResponseDto.class);
    }

    @Override
    public User mapFrom(UserMeResponseDto userMeResponseDto) {
        return modelMapper.map(userMeResponseDto, User.class);
    }
}
