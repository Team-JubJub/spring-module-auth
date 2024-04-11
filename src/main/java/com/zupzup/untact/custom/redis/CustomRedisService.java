package com.zupzup.untact.custom.redis;

import com.zupzup.untact.auth.redis.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class CustomRedisService extends RedisService {

    public CustomRedisService(StringRedisTemplate stringRedisTemplate) {
        super(stringRedisTemplate);
    }
}
