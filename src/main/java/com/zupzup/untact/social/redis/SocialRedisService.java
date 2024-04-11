package com.zupzup.untact.social.redis;

import com.zupzup.untact.auth.redis.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class SocialRedisService extends RedisService {

    public SocialRedisService(StringRedisTemplate stringRedisTemplate) {
        super(stringRedisTemplate);
    }
}
