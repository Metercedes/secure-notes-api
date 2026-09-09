package com.metercedes.securenotes.dto;

import com.metercedes.securenotes.validator.StrongPassword;
import com.metercedes.securenotes.validator.UsernameRule;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 4, max = 20, message = "Username must be between 4 and 20 characters")
        @UsernameRule
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Size(max = 254)
        String email,

        @NotBlank(message = "Password is required")
        @StrongPassword
        String password) {
}
