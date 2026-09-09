package com.metercedes.securenotes.controller;

import com.metercedes.securenotes.model.User;
import com.metercedes.securenotes.repository.NoteRepository;
import com.metercedes.securenotes.repository.UserRepository;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.transaction.annotation.Transactional;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private static final Set<String> ASSIGNABLE_ROLES = Set.of("ROLE_USER", "ROLE_ADMIN");
    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");

    private final UserRepository userRepository;
    private final NoteRepository noteRepository;

    public AdminController(UserRepository userRepository, NoteRepository noteRepository) {
        this.userRepository = userRepository;
        this.noteRepository = noteRepository;
    }

    /**
     * Deliberately projects a fixed field set. Returning the entity would serialise the BCrypt
     * password hash.
     */
    @GetMapping("/users")
    public List<AdminUserView> listUsers() {
        return userRepository.findAll().stream()
                .map(user -> new AdminUserView(user.getId(), user.getUsername(), user.getEmail(), user.getRole()))
                .toList();
    }

    @GetMapping("/stats")
    public Map<String, Long> stats() {
        return Map.of("totalUsers", userRepository.count(), "totalNotes", noteRepository.count());
    }

    @PatchMapping("/users/{userId}/role")
    @Transactional
    public ResponseEntity<AdminUserView> changeRole(@PathVariable Long userId, @RequestParam String role) {
        if (!ASSIGNABLE_ROLES.contains(role)) {
            return ResponseEntity.badRequest().build();
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NoSuchElementException("User not found"));
        user.setRole(role);
        securityLog.info("Role for user id {} changed to {}", userId, role);
        return ResponseEntity.ok(new AdminUserView(user.getId(), user.getUsername(), user.getEmail(), user.getRole()));
    }

    public record AdminUserView(Long id, String username, String email, String role) {
    }
}
