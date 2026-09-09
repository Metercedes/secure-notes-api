package com.metercedes.securenotes.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Resolves the address used as the rate-limiting key.
 *
 * <p>X-Forwarded-For is attacker-controlled unless a trusted reverse proxy overwrites it, so
 * honouring it by default lets a single client defeat rate limiting by rotating the header.
 * It is therefore only consulted when the deployment explicitly declares that it sits behind
 * a trusted proxy.
 */
@Component
public class ClientAddressResolver {

    private final boolean trustForwardedHeaders;

    public ClientAddressResolver(@Value("${security.rate-limit.trust-forwarded-for:false}") boolean trustForwardedHeaders) {
        this.trustForwardedHeaders = trustForwardedHeaders;
    }

    public String resolve(HttpServletRequest request) {
        if (trustForwardedHeaders) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }
}
