package com.rejs.token_starter.token;

import io.jsonwebtoken.Claims;

public class ClaimsDto {
    private final String username;
    private final String role;
    private final String type;

    public ClaimsDto(Claims claims) {
        this.username = claims.getSubject();
        this.role = claims.get("role", String.class);
        this.type = claims.get("type", String.class);
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getType() {
        return type;
    }
}
