package com.metercedes.securenotes.dto;

public record AuthResponse(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) {

    public AuthResponse(String accessToken, String refreshToken, long expiresInSeconds) {
        this(accessToken, refreshToken, "Bearer", expiresInSeconds);
    }
}
