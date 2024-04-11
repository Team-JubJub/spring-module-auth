package com.zupzup.untact.custom.jwt;

import com.zupzup.untact.auth.jwt.JwtTokenProvider;
import com.zupzup.untact.custom.redis.CustomRedisService;
import com.zupzup.untact.custom.service.CustomSellerDetailsService;
import com.zupzup.untact.model.dto.auth.token.seller.SellerRefreshResultDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CustomJwtTokenProvider extends JwtTokenProvider {

    private final CustomRedisService customRedisService;
    private final CustomSellerDetailsService customSellerDetailsService;

    public CustomJwtTokenProvider(CustomRedisService customRedisService, CustomSellerDetailsService customSellerDetailsService, CustomRedisService redisService, CustomSellerDetailsService customSellerDetailsService1) {
        super(customRedisService, customSellerDetailsService);
        this.customRedisService = redisService;
        this.customSellerDetailsService = customSellerDetailsService1;
    }

    public SellerRefreshResultDto validateRefreshToken(String refreshToken)  // refresh token 유효성 검증, 새로운 access token 발급
    {
        List<String> findInfo = customRedisService.getListValue(refreshToken);    // 0 = loginId, 1 = refreshToken
        if (findInfo.get(0) == null) { // 유저 정보가 없으면 FAILED 반환
            return new SellerRefreshResultDto(FAIL_STRING, "No user found", null, null);
        }
        if (validateToken(refreshToken))  // refresh Token 유효성 검증 완료 시
        {
            UserDetails findSeller = customSellerDetailsService.loadSellerByLoginId((String)findInfo.get(0));
            List<String> roles = findSeller.getAuthorities().stream().map(authority -> authority.getAuthority()).collect(Collectors.toList());
            String newAccessToken = generateAccessToken((String)findInfo.get(0), roles);
            return new SellerRefreshResultDto(SUCCESS_STRING, "Access token refreshed", newAccessToken, findInfo.get(0));
        }
        return new SellerRefreshResultDto(FAIL_STRING, "Refresh token expired", null, null);  // refresh Token 만료 시
    }
}
