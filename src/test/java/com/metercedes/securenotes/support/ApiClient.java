package com.metercedes.securenotes.support;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.metercedes.securenotes.dto.LoginRequest;
import com.metercedes.securenotes.dto.RegisterRequest;
import com.metercedes.securenotes.dto.TokenRefreshRequest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Test helper that drives the public HTTP surface, so tests exercise the real filter chain. */
public final class ApiClient {

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;

    public ApiClient(MockMvc mockMvc, ObjectMapper objectMapper) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
    }

    public ResultActions register(String username, String email, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(new RegisterRequest(username, email, password))));
    }

    public ResultActions login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(new LoginRequest(username, password))));
    }

    public ResultActions refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(new TokenRefreshRequest(refreshToken))));
    }

    public Tokens registerAndCollectTokens(String username, String password) throws Exception {
        String body = register(username, username + "@example.test", password)
                .andReturn().getResponse().getContentAsString();
        JsonNode node = objectMapper.readTree(body);
        return new Tokens(node.get("accessToken").stringValue(), node.get("refreshToken").stringValue());
    }

    public String json(Object value) throws Exception {
        return objectMapper.writeValueAsString(value);
    }

    public record Tokens(String accessToken, String refreshToken) {

        public String bearer() {
            return "Bearer " + accessToken;
        }
    }
}
