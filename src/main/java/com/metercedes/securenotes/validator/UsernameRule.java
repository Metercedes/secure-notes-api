package com.metercedes.securenotes.validator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.FIELD}) @Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UsernameValidator.class)
public @interface UsernameRule {
    String message() default "Username must be alphanumeric";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}