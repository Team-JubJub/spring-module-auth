package com.zupzup.untact.social.utils;

import com.zupzup.untact.model.domain.auth.user.User;
import com.zupzup.untact.repository.UserRepository;
import com.zupzup.untact.social.jwt.SocialJwtTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class AuthUtils {

    private final UserRepository userRepository;
    private final SocialJwtTokenProvider jwtTokenProvider;

    public User getUserEntity(String accessToken) {
        String providerUserId = jwtTokenProvider.getProviderUserId(accessToken);    // 유저의 id 조회
        User userEntity = userRepository.findByProviderUserId(providerUserId).get();

        return userEntity;
    }

}
