package com.metercedes.securenotes.service;

import com.metercedes.securenotes.model.RefreshToken;
import com.metercedes.securenotes.model.User;
import com.metercedes.securenotes.repository.RefreshTokenRepository;
import com.metercedes.securenotes.repository.UserRepository;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Revocation is a separate bean so that {@code REQUIRES_NEW} actually takes effect: a call made
 * from inside {@link RefreshTokenService} to one of its own methods would bypass the proxy and
 * silently join the caller's transaction.
 */
@Component
public class RefreshTokenRevocations {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenRevocations(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    /**
     * Commits independently of the caller, so a replay that ends in a rolled-back transaction
     * still leaves every token for the account revoked.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeAllForUserId(Long userId) {
        userRepository.findById(userId).ifPresent(this::revokeAll);
    }

    @Transactional
    public void revokeAllForUsername(String username) {
        userRepository.findByUsername(username).ifPresent(this::revokeAll);
    }

    private void revokeAll(User user) {
        Instant now = Instant.now();
        List<RefreshToken> active = refreshTokenRepository.findByUserAndRevokedAtIsNull(user);
        active.forEach(token -> token.revoke(now));
        refreshTokenRepository.saveAll(active);
    }
}
