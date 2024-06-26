package com.zupzup.untact.social.service;

import com.zupzup.untact.social.dto.LoginInfoDto;
import com.zupzup.untact.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService { // jwtTokenProvider에서 user 정보 load 할 때 사용

    private final UserRepository userRepository;

    public UserDetails loadUserByProviderUserId(String providerUserId) {
        return new LoginInfoDto(userRepository.findByProviderUserId(providerUserId).get());
    }

}
