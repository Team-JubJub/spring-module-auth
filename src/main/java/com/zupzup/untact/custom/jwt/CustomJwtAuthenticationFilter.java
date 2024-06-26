package com.zupzup.untact.custom.jwt;

import com.zupzup.untact.exception.auth.BlackListTokenException;
import com.zupzup.untact.exception.auth.RefreshRequiredException;
import com.zupzup.untact.exception.auth.RequiredHeaderNotExistException;
import com.zupzup.untact.exception.auth.SignFailedException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomJwtAuthenticationFilter extends OncePerRequestFilter {

    private final CustomJwtTokenProvider jwtTokenProvider;

    // JwtAuthenticationFilter를 filterChain에 등록
    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String accessToken = jwtTokenProvider.resolveToken(request, jwtTokenProvider.ACCESS_TOKEN_NAME);
        if (accessToken == null) throw new RequiredHeaderNotExistException(jwtTokenProvider.ACCESS_TOKEN_NAME);

        if (!jwtTokenProvider.isRedisBlackList(accessToken)) {   // 로그아웃 된 상황이 아니라면(redis refreshToken 테이블에 accessToken이 저장된 게 아니라면)
            try {
                if (jwtTokenProvider.validateToken(accessToken)) {   // access token이 만료되지 않았을 경우
                    Authentication auth = jwtTokenProvider.getAuthentication(accessToken);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (ExpiredJwtException e) {   // validateToken의 claims.getBody().getExpiration()에서 발생
                System.out.println("Token expired");
                throw new RefreshRequiredException();
            } catch (SignatureException e) {
                throw new SignFailedException();
            } catch (MalformedJwtException e) {
                throw new MalformedJwtException("Provided JWT token's format is not correct.");
            }
        }
        else {  // 로그아웃 혹은 회원탈퇴한 유저
            System.out.println("Sign-outed or deleted user");
            throw new BlackListTokenException();
        }

        filterChain.doFilter(request, response);
    }
}
