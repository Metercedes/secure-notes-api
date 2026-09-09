package com.metercedes.securenotes.controller;

import com.metercedes.securenotes.dto.NoteDto;
import com.metercedes.securenotes.model.User;
import com.metercedes.securenotes.support.ApiClient;
import com.metercedes.securenotes.support.IntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Negative authorisation tests. Every one of these asserts that a request which should be
 * refused actually is refused; a change that widens access breaks this class.
 */
class AccessControlIntegrationTest extends IntegrationTestBase {

    private ApiClient.Tokens owner;
    private ApiClient.Tokens intruder;
    private long ownedNoteId;

    @BeforeEach
    void createFixtures() throws Exception {
        owner = api.registerAndCollectTokens("owner", PASSWORD);
        intruder = api.registerAndCollectTokens("intruder", PASSWORD);

        String created = mockMvc.perform(post("/api/notes")
                        .header("Authorization", owner.bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(api.json(new NoteDto(null, "Owner note", "secret content"))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        ownedNoteId = objectMapper.readTree(created).get("id").asLong();
    }

    @Nested
    @DisplayName("Unauthenticated access")
    class Unauthenticated {

        @Test
        @DisplayName("cannot list notes")
        void cannotListNotes() throws Exception {
            mockMvc.perform(get("/api/notes")).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("cannot read a note by id")
        void cannotReadNote() throws Exception {
            mockMvc.perform(get("/api/notes/" + ownedNoteId)).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("cannot reach admin endpoints")
        void cannotReachAdmin() throws Exception {
            mockMvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("a forged bearer token is rejected")
        void rejectsForgedToken() throws Exception {
            mockMvc.perform(get("/api/notes")
                            .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.forged"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Cross-user access (IDOR)")
    class CrossUser {

        @Test
        @DisplayName("another user cannot read the note")
        void cannotRead() throws Exception {
            mockMvc.perform(get("/api/notes/" + ownedNoteId).header("Authorization", intruder.bearer()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("another user cannot replace the note")
        void cannotReplace() throws Exception {
            mockMvc.perform(put("/api/notes/" + ownedNoteId)
                            .header("Authorization", intruder.bearer())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(api.json(new NoteDto(null, "hijacked", "hijacked"))))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("another user cannot patch the note")
        void cannotPatch() throws Exception {
            mockMvc.perform(patch("/api/notes/" + ownedNoteId)
                            .header("Authorization", intruder.bearer())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(api.json(new NoteDto(null, null, "hijacked"))))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("another user cannot delete the note")
        void cannotDelete() throws Exception {
            mockMvc.perform(delete("/api/notes/" + ownedNoteId).header("Authorization", intruder.bearer()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("the note survives every attempt")
        void noteIsUnchanged() throws Exception {
            mockMvc.perform(delete("/api/notes/" + ownedNoteId).header("Authorization", intruder.bearer()));
            mockMvc.perform(get("/api/notes/" + ownedNoteId).header("Authorization", owner.bearer()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.content").value("secret content"));
        }

        @Test
        @DisplayName("listing only returns the caller's own notes")
        void listingIsScopedToCaller() throws Exception {
            mockMvc.perform(get("/api/notes").header("Authorization", intruder.bearer()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(0));
        }
    }

    @Nested
    @DisplayName("Role enforcement")
    class Roles {

        @Test
        @DisplayName("a normal user is refused admin endpoints")
        void userCannotListUsers() throws Exception {
            mockMvc.perform(get("/api/admin/users").header("Authorization", owner.bearer()))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("a normal user cannot change roles")
        void userCannotChangeRoles() throws Exception {
            long targetId = userRepository.findByUsername("intruder").orElseThrow().getId();
            mockMvc.perform(patch("/api/admin/users/" + targetId + "/role")
                            .header("Authorization", owner.bearer())
                            .param("role", "ROLE_ADMIN"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("registration always assigns ROLE_USER and cannot self-elevate")
        void registrationCannotElevate() throws Exception {
            mockMvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                            {"username":"climber","email":"climber@example.test",
                             "password":"SecureP@ss1","role":"ROLE_ADMIN"}"""));
            User created = userRepository.findByUsername("climber").orElseThrow();
            org.assertj.core.api.Assertions.assertThat(created.getRole()).isEqualTo("ROLE_USER");
        }

        @Test
        @DisplayName("an admin can list users without any password hash in the response")
        void adminListingOmitsPasswordHash() throws Exception {
            User user = userRepository.findByUsername("owner").orElseThrow();
            user.setRole("ROLE_ADMIN");
            userRepository.save(user);

            ApiClient.Tokens adminTokens = new ApiClient.Tokens(
                    objectMapper.readTree(api.login("owner", PASSWORD).andReturn()
                            .getResponse().getContentAsString()).get("accessToken").stringValue(), "");

            mockMvc.perform(get("/api/admin/users").header("Authorization", adminTokens.bearer()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].password").doesNotExist())
                    .andExpect(jsonPath("$[0].username").isNotEmpty());
        }
    }

    @Nested
    @DisplayName("Input validation")
    class Validation {

        @Test
        @DisplayName("rejects a note without a title")
        void rejectsMissingTitle() throws Exception {
            mockMvc.perform(post("/api/notes")
                            .header("Authorization", owner.bearer())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(api.json(new NoteDto(null, "  ", "body"))))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("rejects an oversized title")
        void rejectsOversizedTitle() throws Exception {
            mockMvc.perform(post("/api/notes")
                            .header("Authorization", owner.bearer())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(api.json(new NoteDto(null, "x".repeat(201), "body"))))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("stores note content verbatim without interpreting it")
        void storesContentVerbatim() throws Exception {
            String payload = "<script>alert(1)</script>' OR 1=1--";
            String created = mockMvc.perform(post("/api/notes")
                            .header("Authorization", owner.bearer())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(api.json(new NoteDto(null, "payload", payload))))
                    .andExpect(status().isCreated())
                    .andReturn().getResponse().getContentAsString();

            long id = objectMapper.readTree(created).get("id").asLong();
            mockMvc.perform(get("/api/notes/" + id).header("Authorization", owner.bearer()))
                    .andExpect(jsonPath("$.content").value(payload));
        }
    }
}
