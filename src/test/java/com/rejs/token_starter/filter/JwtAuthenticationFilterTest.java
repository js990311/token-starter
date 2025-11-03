package com.rejs.token_starter.filter;

import com.rejs.token_starter.token.JwtUtils;
import com.rejs.token_starter.token.Tokens;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
@Import({JwtAuthenticationFilterTest.TestConfig.class, JwtAuthenticationFilterTest.TestController.class})
class JwtAuthenticationFilterTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtils jwtUtils;

    String username = "username";
    String role = "role";

    @Test
    void testAccessToken() throws Exception {
        Tokens tokens = jwtUtils.generateToken(username, role);
        ResultActions result = mockMvc.perform(get("/test").header("Authorization", "Bearer " + tokens.getAccessToken()));
        result.andExpect(status().isOk());
    }

    @Test
    void testRefreshToken() throws Exception {
        Tokens tokens = jwtUtils.generateToken(username, role);
        ResultActions result = mockMvc.perform(get("/test").header("Authorization", "Bearer " +  tokens.getRefreshToken()));
        result.andExpect(status().isForbidden());
    }

    @Test
    void testNotTOken() throws Exception {
        Tokens tokens = jwtUtils.generateToken(username, role);
        ResultActions result = mockMvc.perform(get("/test").header("Authorization", "Bearer " +  tokens.getRefreshToken()));
        result.andExpect(status().isForbidden());
    }



    @RestController
    static class TestController{
        @GetMapping("/test")
        public Map<String, String > test(){
            return Map.of("key", "value");
        }
    }

    @Configuration
    static class TestConfig {
        @Bean
        public JwtUtils jwtUtils() {
            long accessExpiration = 1000 * 60;
            long refreshExpiration = 1000 * 60 * 60;
            String secretKey = Encoders.BASE64.encode(Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded());
            return new JwtUtils(secretKey, accessExpiration, refreshExpiration);
        }

        @Bean
        public JwtAuthenticationFilter jwtAuthenticationFilter(){
            return new JwtAuthenticationFilter(jwtUtils());
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/test").authenticated()
                            .anyRequest().permitAll()
                    )
            ;
            return http.build();
        }
    }

}