package com.metercedes.securenotes.validator;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class UsernameValidatorTest {

    private UsernameValidator validator;

    @Mock
    private ConstraintValidatorContext context;

    @BeforeEach
    void setUp() {
        validator = new UsernameValidator();
    }

    @Nested
    @DisplayName("Valid username tests")
    class ValidUsernameTests {

        @ParameterizedTest
        @ValueSource(strings = {
                "john",
                "John123",
                "USER",
                "user123test",
                "a1b2c3",
                "ABC123xyz"
        })
        @DisplayName("Should accept alphanumeric usernames")
        void isValid_shouldAcceptAlphanumericUsernames(String username) {
            boolean result = validator.isValid(username, context);
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should accept single character username")
        void isValid_shouldAcceptSingleChar() {
            assertThat(validator.isValid("a", context)).isTrue();
            assertThat(validator.isValid("1", context)).isTrue();
        }
    }

    @Nested
    @DisplayName("Invalid username tests")
    class InvalidUsernameTests {

        @ParameterizedTest
        @ValueSource(strings = {
                "john_doe",
                "john-doe",
                "john.doe",
                "john@doe",
                "john doe",
                "john!",
                "user#123",
                "user$test",
                "test%user"
        })
        @DisplayName("Should reject usernames with special characters")
        void isValid_shouldRejectSpecialCharacters(String username) {
            boolean result = validator.isValid(username, context);
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject null username")
        void isValid_shouldRejectNullUsername() {
            boolean result = validator.isValid(null, context);
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject empty username")
        void isValid_shouldRejectEmptyUsername() {
            boolean result = validator.isValid("", context);
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject username with only spaces")
        void isValid_shouldRejectOnlySpaces() {
            boolean result = validator.isValid("   ", context);
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject username with unicode characters")
        void isValid_shouldRejectUnicodeChars() {
            assertThat(validator.isValid("usér", context)).isFalse();
            assertThat(validator.isValid("用户", context)).isFalse();
            assertThat(validator.isValid("пользователь", context)).isFalse();
        }
    }
}
