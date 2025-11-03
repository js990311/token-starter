package com.rejs.token_starter.token;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;

import java.beans.Encoder;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {
    private JwtUtils jwtUtils;
    private final long accessExpiration = 1000 * 60;
    private final long refreshExpiration = 1000 * 60 * 60;

    private String username = "username";
    private String role = "ROLE_USER";

    @BeforeEach
    void setUp(){
        String secretKey = Encoders.BASE64.encode(Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded());
        jwtUtils = new JwtUtils(secretKey, accessExpiration, refreshExpiration);
    }

    @Test
    void generateToken() {
        Tokens tokens = jwtUtils.generateToken(username, role);
        assertNotNull(tokens);
        assertNotNull(tokens.getAccessToken());
        assertNotNull(tokens.getRefreshToken());
    }

    @Test
    void validateAccessToken() {
        Tokens tokens = jwtUtils.generateToken(username, role);
        assertTrue(jwtUtils.validateAccessToken(tokens.getAccessToken()));
    }

    @Test
    void validateRefreshToken() {
        Tokens tokens = jwtUtils.generateToken(username, role);
        assertTrue(jwtUtils.validateRefreshToken(tokens.getRefreshToken()));
    }

    @Test
    void getClaims(){
        Tokens tokens = jwtUtils.generateToken(username, role);
        ClaimsDto claims = jwtUtils.getClaims(tokens.getAccessToken());
        assertEquals(username, claims.getUsername());
        assertEquals(role, claims.getRole());
    }
}