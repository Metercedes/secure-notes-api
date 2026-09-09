package com.metercedes.securenotes.validator;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
public class UsernameValidator implements ConstraintValidator<UsernameRule, String> {
    public boolean isValid(String v, ConstraintValidatorContext c) {
        return v != null && v.matches("^[a-zA-Z0-9]+$");
    }
}