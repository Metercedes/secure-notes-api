package com.metercedes.securenotes.service;

import com.metercedes.securenotes.dto.RegisterRequest;
import com.metercedes.securenotes.model.User;
import com.metercedes.securenotes.repository.UserRepository;
import java.util.NoSuchElementException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Registration always assigns ROLE_USER. The role is never taken from the request body,
     * so registration cannot be used to escalate privileges.
     */
    @Transactional
    public User register(RegisterRequest request) {
        if (repository.existsByUsername(request.username())) {
            throw new DuplicateAccountException("Username is already taken");
        }
        if (repository.existsByEmail(request.email())) {
            throw new DuplicateAccountException("Email is already registered");
        }
        User user = new User(request.username(), request.email(),
                passwordEncoder.encode(request.password()), "ROLE_USER");
        return repository.save(user);
    }

    public User getByUsername(String username) {
        return repository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("User not found"));
    }

    public User getUserById(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("User not found"));
    }

    public static class DuplicateAccountException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public DuplicateAccountException(String message) {
            super(message);
        }
    }
}
