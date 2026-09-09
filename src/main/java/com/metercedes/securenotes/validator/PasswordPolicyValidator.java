package com.metercedes.securenotes.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Set;

public class PasswordPolicyValidator implements ConstraintValidator<StrongPassword, String> {

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "12345678", "123456789", "qwerty123", "password1",
            "password123", "admin123", "letmein123", "welcome123", "monkey123",
            "dragon123", "master123", "qwertyuiop", "iloveyou1", "trustno1",
            "sunshine1", "princess1", "football1", "baseball1", "shadow123",
            "superman1", "michael123", "jennifer1", "abcdef123", "abc12345"
    );

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isBlank()) {
            return false;
        }

        context.disableDefaultConstraintViolation();

        boolean valid = true;

        if (password.length() < 8) {
            context.buildConstraintViolationWithTemplate("Password must be at least 8 characters")
                    .addConstraintViolation();
            valid = false;
        }

        if (!password.matches(".*[A-Z].*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one uppercase letter")
                    .addConstraintViolation();
            valid = false;
        }

        if (!password.matches(".*[a-z].*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one lowercase letter")
                    .addConstraintViolation();
            valid = false;
        }

        if (!password.matches(".*\\d.*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one digit")
                    .addConstraintViolation();
            valid = false;
        }


        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)")
                    .addConstraintViolation();
            valid = false;
        }

        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            context.buildConstraintViolationWithTemplate("Password is too common and easily guessable")
                    .addConstraintViolation();
            valid = false;
        }

        return valid;
    }
}
