package com.metercedes.securenotes.support;

import com.metercedes.securenotes.repository.NoteRepository;
import com.metercedes.securenotes.repository.RefreshTokenRepository;
import com.metercedes.securenotes.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared setup for tests that drive the real filter chain. The schema is emptied before each
 * test so ordering cannot make one test depend on another's data.
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class IntegrationTestBase {

    protected static final String PASSWORD = "SecureP@ss1";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected NoteRepository noteRepository;

    @Autowired
    protected RefreshTokenRepository refreshTokenRepository;

    protected ApiClient api;

    @BeforeEach
    void resetState() {
        refreshTokenRepository.deleteAll();
        noteRepository.deleteAll();
        userRepository.deleteAll();
        api = new ApiClient(mockMvc, objectMapper);
    }
}
