package com.rejs.token_starter.config;

import com.rejs.token_starter.filter.JwtAuthenticationFilter;
import com.rejs.token_starter.token.JwtUtils;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@ActiveProfiles("test")
class AutoJwtTokenConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AutoJwtTokenConfiguration.class));

    @Test
    void testPropertiesHasSecretKey(){
        String key = "2D4nHTKcWRmpMJAvAgl1eSq4jWtfv0mdLK9BEHmMSeQ=";
        long accessTokenExpiration = 1000 * 60 * 60;
        long refreshTokenExpiration = 1000 * 60 * 60 * 24 * 7;
        contextRunner.withPropertyValues("jwt.secret-key=" + key)
                .run(context -> {
                    assertThat(context).hasSingleBean(JwtProperties.class);
                    assertThat(context).hasSingleBean(JwtUtils.class);
                    JwtProperties properties = context.getBean(JwtProperties.class);

                    assertEquals(key, properties.getSecretKey());
                    assertEquals(accessTokenExpiration, properties.getAccessTokenExpiration());
                    assertEquals(refreshTokenExpiration, properties.getRefreshTokenExpiration());
                });
    }

    @Test
    void testPropertiesHasProperties(){
        String key = "2D4nHTKcWRmpMJAvAgl1eSq4jWtfv0mdLK9BEHmMSeQ=";
        long accessTokenExpiration = 1000 * 60 * 60 * 123 ;
        long refreshTokenExpiration = 1000 * 60 * 60 * 456;

        contextRunner.withPropertyValues(
                "jwt.secret-key=" + key,
                        "jwt.access-token-expiration=" + accessTokenExpiration,
                        "jwt.refresh-token-expiration=" + refreshTokenExpiration
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(JwtProperties.class);
                    assertThat(context).hasSingleBean(JwtUtils.class);
                    JwtProperties properties = context.getBean(JwtProperties.class);

                    assertEquals(key, properties.getSecretKey());
                    assertEquals(accessTokenExpiration, properties.getAccessTokenExpiration());
                    assertEquals(refreshTokenExpiration, properties.getRefreshTokenExpiration());
                });
    }

    @Test
    void testPropertiesIsEmpty(){
        contextRunner.withPropertyValues()
                .run(context -> {
                    assertThat(context).hasFailed();
                });
    }

}