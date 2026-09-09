package com.metercedes.securenotes.controller;

import com.metercedes.securenotes.dto.AuthResponse;
import com.metercedes.securenotes.dto.LoginRequest;
import com.metercedes.securenotes.dto.RegisterRequest;
import com.metercedes.securenotes.dto.TokenRefreshRequest;
import com.metercedes.securenotes.security.JwtService;
import com.metercedes.securenotes.service.RefreshTokenService;
import com.metercedes.securenotes.service.UserService;
import jakarta.validation.Valid;
import java.security.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsService userDetailsService,
                          UserService userService,
                          JwtService jwtService,
                          RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.userService = userService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        userService.register(request);
        securityLog.info("Account registered: {}", request.username());
        return ResponseEntity.status(HttpStatus.CREATED).body(issueTokens(request.username()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        } catch (AuthenticationException e) {
            securityLog.warn("Failed login for username: {}", request.username());
            throw e;
        }
        securityLog.info("Successful login: {}", request.username());
        return ResponseEntity.ok(issueTokens(request.username()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody TokenRefreshRequest request) {
        RefreshTokenService.RotationResult result = refreshTokenService.rotate(request.refreshToken());
        UserDetails userDetails = userDetailsService.loadUserByUsername(result.user().getUsername());
        String accessToken = jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(accessToken, result.token().token(),
                jwtService.accessTokenTtlSeconds()));
    }

    /**
     * Revokes the caller's own sessions only. The account is taken from the authenticated
     * principal rather than the request body, so one user cannot terminate another user's sessions.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Principal principal) {
        refreshTokenService.revokeAllFor(principal.getName());
        securityLog.info("Sessions revoked for: {}", principal.getName());
        return ResponseEntity.noContent().build();
    }

    private AuthResponse issueTokens(String username) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String accessToken = jwtService.generateToken(userDetails);
        RefreshTokenService.IssuedToken refresh = refreshTokenService.issue(username);
        return new AuthResponse(accessToken, refresh.token(), jwtService.accessTokenTtlSeconds());
    }
}
