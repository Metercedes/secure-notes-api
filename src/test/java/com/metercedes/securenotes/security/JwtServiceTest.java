package com.metercedes.securenotes.security;

import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String VALID_SECRET =
            Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes());

    private static final UserDetails ALICE = User.withUsername("alice").password("x").roles("USER").build();
    private static final UserDetails BOB = User.withUsername("bob").password("x").roles("USER").build();

    private JwtService service(String secret, Duration ttl) {
        return new JwtService(secret, ttl);
    }

    @Test
    @DisplayName("refuses to start when the signing key is shorter than 256 bits")
    void rejectsShortKey() {
        String shortKey = Base64.getEncoder().encodeToString("too-short".getBytes());
        assertThatThrownBy(() -> service(shortKey, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("256 bits");
    }

    @Test
    @DisplayName("refuses to start when the signing key is not Base64")
    void rejectsNonBase64Key() {
        assertThatThrownBy(() -> service("!!! not base64 !!!", Duration.ofMinutes(15)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Base64");
    }

    @Test
    @DisplayName("round-trips the subject")
    void roundTripsSubject() {
        JwtService jwt = service(VALID_SECRET, Duration.ofMinutes(15));
        assertThat(jwt.extractUsername(jwt.generateToken(ALICE))).isEqualTo("alice");
    }

    @Test
    @DisplayName("a token issued for one user is not valid for another")
    void rejectsSubjectMismatch() {
        JwtService jwt = service(VALID_SECRET, Duration.ofMinutes(15));
        assertThat(jwt.isTokenValid(jwt.generateToken(ALICE), BOB)).isFalse();
    }

    @Test
    @DisplayName("an expired token is invalid")
    void rejectsExpiredToken() throws Exception {
        JwtService jwt = service(VALID_SECRET, Duration.ofMillis(1));
        String token = jwt.generateToken(ALICE);
        Thread.sleep(20);
        assertThat(jwt.isTokenValid(token, ALICE)).isFalse();
    }

    @Test
    @DisplayName("a token signed with a different key is rejected rather than trusted")
    void rejectsForeignSignature() {
        String otherSecret = Base64.getEncoder().encodeToString("ffffffffffffffffffffffffffffffff".getBytes());
        String foreign = service(otherSecret, Duration.ofMinutes(15)).generateToken(ALICE);
        assertThat(service(VALID_SECRET, Duration.ofMinutes(15)).isTokenValid(foreign, ALICE)).isFalse();
    }

    @Test
    @DisplayName("an unsigned 'alg: none' token is rejected")
    void rejectsUnsignedToken() {
        String header = base64Url("{\"alg\":\"none\"}");
        String payload = base64Url("{\"sub\":\"alice\",\"iss\":\"secure-notes-api\"}");
        String unsigned = header + "." + payload + ".";
        assertThat(service(VALID_SECRET, Duration.ofMinutes(15)).isTokenValid(unsigned, ALICE)).isFalse();
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes());
    }
}
