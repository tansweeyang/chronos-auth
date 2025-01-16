package dev.eislyn.chronos_auth.mappers.impl;

import dev.eislyn.chronos_auth.dto.response.UserMeResponse;
import dev.eislyn.chronos_auth.mappers.Mapper;
import dev.eislyn.chronos_auth.model.User;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
public class UserMapperImpl implements Mapper<User, UserMeResponse> {
    private ModelMapper modelMapper;

    public UserMapperImpl(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }

    @Override
    public UserMeResponse mapTo(User user) {
        return modelMapper.map(user, UserMeResponse.class);
    }

    @Override
    public User mapFrom(UserMeResponse userMeResponse) {
        return modelMapper.map(userMeResponse, User.class);
    }
}
