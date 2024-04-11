package com.zupzup.untact.custom.jwt;

import com.zupzup.untact.auth.jwt.JwtTokenProvider;

public class CustomJwtAuthenticationFilter extends com.zupzup.untact.auth.jwt.JwtAuthenticationFilter {

    public CustomJwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        super(jwtTokenProvider);
    }
}
