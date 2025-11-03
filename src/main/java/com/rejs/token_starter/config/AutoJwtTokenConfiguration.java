package com.rejs.token_starter.config;

import ch.qos.logback.core.util.StringUtil;
import com.rejs.token_starter.filter.JwtAuthenticationFilter;
import com.rejs.token_starter.token.JwtUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class AutoJwtTokenConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public JwtUtils jwtUtils(JwtProperties properties){
        if(!StringUtils.hasText(properties.getSecretKey())){
            throw new IllegalArgumentException("Require jwt.secret-key in Properties");
        }
        return new JwtUtils(
                properties.getSecretKey(),
                properties.getAccessTokenExpiration(),
                properties.getRefreshTokenExpiration()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtils jwtUtils){
        return new JwtAuthenticationFilter(jwtUtils);
    }
}
