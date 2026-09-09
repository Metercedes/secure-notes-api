package com.metercedes.securenotes.controller;

import com.metercedes.securenotes.support.ApiClient;
import com.metercedes.securenotes.support.IntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthIntegrationTest extends IntegrationTestBase {

    @Nested
    @DisplayName("Registration")
    class Registration {

        @Test
        @DisplayName("issues an access and refresh token pair")
        void registersAndIssuesTokens() throws Exception {
            api.register("alice", "alice@example.test", PASSWORD)
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"));
        }

        @ParameterizedTest(name = "rejects weak password \"{0}\"")
        @ValueSource(strings = {"short", "alllowercase1!", "NOUPPERCASE1!", "NoDigitsHere!", "NoSpecial123"})
        void rejectsWeakPasswords(String password) throws Exception {
            api.register("bob", "bob@example.test", password).andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("rejects a duplicate username with 409")
        void rejectsDuplicateUsername() throws Exception {
            api.register("carol", "carol@example.test", PASSWORD).andExpect(status().isCreated());
            api.register("carol", "other@example.test", PASSWORD).andExpect(status().isConflict());
        }

        @Test
        @DisplayName("rejects a duplicate email with 409")
        void rejectsDuplicateEmail() throws Exception {
            api.register("dave", "shared@example.test", PASSWORD).andExpect(status().isCreated());
            api.register("erin", "shared@example.test", PASSWORD).andExpect(status().isConflict());
        }

        @Test
        @DisplayName("never returns the stored password hash")
        void doesNotLeakPasswordHash() throws Exception {
            api.register("frank", "frank@example.test", PASSWORD)
                    .andExpect(jsonPath("$.password").doesNotExist());
        }
    }

    @Nested
    @DisplayName("Login")
    class Login {

        @BeforeEach
        void createAccount() throws Exception {
            api.register("grace", "grace@example.test", PASSWORD);
        }

        @Test
        @DisplayName("returns tokens for correct credentials")
        void succeedsWithValidCredentials() throws Exception {
            api.login("grace", PASSWORD)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty());
        }

        @Test
        @DisplayName("returns 401 for a wrong password")
        void rejectsWrongPassword() throws Exception {
            api.login("grace", "WrongP@ss1").andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("returns the same 401 for an unknown user, so accounts cannot be enumerated")
        void doesNotDistinguishUnknownUser() throws Exception {
            api.login("nobody", PASSWORD)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.details").value("Invalid username or password"));
        }
    }

    @Nested
    @DisplayName("Refresh token rotation")
    class Rotation {

        @Test
        @DisplayName("rotation returns a different refresh token")
        void rotationIssuesNewToken() throws Exception {
            ApiClient.Tokens tokens = api.registerAndCollectTokens("heidi", PASSWORD);
            api.refresh(tokens.refreshToken())
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                    .andExpect(jsonPath("$.refreshToken").value(
                            org.hamcrest.Matchers.not(tokens.refreshToken())));
        }

        @Test
        @DisplayName("a rotated token cannot be reused")
        void rejectsReuseOfRotatedToken() throws Exception {
            ApiClient.Tokens tokens = api.registerAndCollectTokens("ivan", PASSWORD);
            api.refresh(tokens.refreshToken()).andExpect(status().isOk());
            api.refresh(tokens.refreshToken()).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("replaying a used token also revokes the replacement token")
        void replayRevokesEntireTokenFamily() throws Exception {
            ApiClient.Tokens tokens = api.registerAndCollectTokens("judy", PASSWORD);
            String rotated = objectMapper.readTree(api.refresh(tokens.refreshToken())
                    .andReturn().getResponse().getContentAsString()).get("refreshToken").stringValue();

            api.refresh(tokens.refreshToken()).andExpect(status().isUnauthorized());

            api.refresh(rotated).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("rejects an unknown refresh token")
        void rejectsUnknownToken() throws Exception {
            api.refresh("not-a-real-token").andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Logout")
    class Logout {

        @Test
        @DisplayName("requires authentication, so one user cannot end another user's sessions")
        void requiresAuthentication() throws Exception {
            mockMvc.perform(post("/api/auth/logout")).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("revokes the caller's refresh tokens")
        void revokesCallersTokens() throws Exception {
            ApiClient.Tokens tokens = api.registerAndCollectTokens("mallory", PASSWORD);
            mockMvc.perform(post("/api/auth/logout").header("Authorization", tokens.bearer()))
                    .andExpect(status().isNoContent());
            api.refresh(tokens.refreshToken()).andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Response hardening")
    class ResponseHardening {

        @Test
        @DisplayName("sets the documented security headers")
        void setsSecurityHeaders() throws Exception {
            api.login("nobody", PASSWORD)
                    .andExpect(header().string("X-Frame-Options", "DENY"))
                    .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                    .andExpect(header().string("Referrer-Policy", "no-referrer"))
                    .andExpect(header().exists("Content-Security-Policy"));
        }

        @Test
        @DisplayName("returns 400 without a stack trace for malformed JSON")
        void rejectsMalformedJsonWithoutStackTrace() throws Exception {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\": "))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.trace").doesNotExist());
        }
    }
}
