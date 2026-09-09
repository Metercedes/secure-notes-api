package com.metercedes.securenotes.service;

import com.metercedes.securenotes.exception.InvalidRefreshTokenException;
import com.metercedes.securenotes.model.RefreshToken;
import com.metercedes.securenotes.model.User;
import com.metercedes.securenotes.repository.RefreshTokenRepository;
import com.metercedes.securenotes.repository.UserRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.NoSuchElementException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");
    private static final int TOKEN_BYTES = 32;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final RefreshTokenRevocations revocations;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Duration refreshTokenTtl;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               UserRepository userRepository,
                               RefreshTokenRevocations revocations,
                               @Value("${security.jwt.refresh-expiration}") Duration refreshTokenTtl) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.revocations = revocations;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    /**
     * Issues a new refresh token. The returned value is the only copy of the plaintext token;
     * persistence stores a SHA-256 digest so a database disclosure cannot be replayed against
     * the token endpoint.
     */
    @Transactional
    public IssuedToken issue(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("User not found"));
        return issue(user);
    }

    private IssuedToken issue(User user) {
        byte[] raw = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        RefreshToken stored = new RefreshToken(hash(token), Instant.now().plus(refreshTokenTtl), user);
        refreshTokenRepository.save(stored);
        return new IssuedToken(token, stored.getExpiryDate());
    }

    /**
     * Rotates a refresh token. Presenting an already-revoked token is treated as a replay and
     * revokes every outstanding token for that user, since the plaintext is single-use and a
     * second presentation implies it leaked.
     */
    @Transactional
    public RotationResult rotate(String presentedToken) {
        RefreshToken existing = refreshTokenRepository.findByTokenHash(hash(presentedToken))
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token is not recognised"));

        Instant now = Instant.now();
        if (existing.isRevoked()) {
            securityLog.warn("Refresh token replay detected for user id {}; revoking all sessions",
                    existing.getUser().getId());
            // Committed in its own transaction: rotate() rolls back when it throws below, and the
            // revocation must outlive that rollback or the replay would leave the family usable.
            revocations.revokeAllForUserId(existing.getUser().getId());
            throw new InvalidRefreshTokenException("Refresh token has already been used");
        }
        if (existing.isExpired(now)) {
            existing.revoke(now);
            throw new InvalidRefreshTokenException("Refresh token has expired");
        }

        existing.revoke(now);
        User user = existing.getUser();
        return new RotationResult(user, issue(user));
    }

    public void revokeAllFor(String username) {
        revocations.revokeAllForUsername(username);
    }

    private String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    public record IssuedToken(String token, Instant expiresAt) {
    }

    public record RotationResult(User user, IssuedToken token) {
    }
}
