package com.metercedes.securenotes.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fixed-window per-address request limiter. Authentication endpoints get a tighter window so
 * credential stuffing is slowed independently of ordinary API traffic.
 *
 * <p>State is in-memory and therefore per-instance; a multi-instance deployment needs a shared
 * store. See docs/threat-model.md.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");
    private static final int MAX_TRACKED_CLIENTS = 100_000;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final ClientAddressResolver clientAddressResolver;
    private final boolean enabled;
    private final int generalLimit;
    private final int authLimit;

    public RateLimitingFilter(ClientAddressResolver clientAddressResolver,
                              @Value("${security.rate-limit.enabled:true}") boolean enabled,
                              @Value("${security.rate-limit.requests-per-minute:60}") int generalLimit,
                              @Value("${security.rate-limit.auth-requests-per-minute:10}") int authLimit) {
        this.clientAddressResolver = clientAddressResolver;
        this.enabled = enabled;
        this.generalLimit = generalLimit;
        this.authLimit = authLimit;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (!enabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        int limit = isAuthenticationEndpoint(path) ? authLimit : generalLimit;
        String client = clientAddressResolver.resolve(request);

        if (exceedsLimit(client, path, limit)) {
            securityLog.warn("Rate limit exceeded for {} on {} (limit {}/min)", client, path, limit);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Too Many Requests\",\"details\":\"Rate limit exceeded\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean exceedsLimit(String client, String path, int limit) {
        long minute = System.currentTimeMillis() / 60_000L;
        String key = (isAuthenticationEndpoint(path) ? "auth:" : "api:") + client;

        // Bounds the map so a spoofed-address flood cannot exhaust heap; the window is one
        // minute, so dropping state early only ever resets a counter.
        if (windows.size() > MAX_TRACKED_CLIENTS) {
            windows.entrySet().removeIf(entry -> entry.getValue().minute() < minute);
        }

        Window window = windows.compute(key, (ignored, current) ->
                current == null || current.minute() != minute ? new Window(minute, 1) : current.increment());
        return window.count() > limit;
    }

    private boolean isAuthenticationEndpoint(String path) {
        return path.startsWith("/api/auth/login") || path.startsWith("/api/auth/register")
                || path.startsWith("/api/auth/refresh");
    }

    private record Window(long minute, int count) {
        Window increment() {
            return new Window(minute, count + 1);
        }
    }
}
