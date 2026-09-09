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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordPolicyValidatorTest {

    private PasswordPolicyValidator validator;

    @Mock
    private ConstraintValidatorContext context;

    @Mock
    private ConstraintValidatorContext.ConstraintViolationBuilder violationBuilder;

    @BeforeEach
    void setUp() {
        validator = new PasswordPolicyValidator();
        
        lenient().when(context.buildConstraintViolationWithTemplate(anyString()))
                .thenReturn(violationBuilder);
        lenient().when(violationBuilder.addConstraintViolation())
                .thenReturn(context);
    }

    @Nested
    @DisplayName("Valid password tests")
    class ValidPasswordTests {

        @Test
        @DisplayName("Should accept password meeting all requirements")
        void isValid_shouldAcceptStrongPassword() {
            boolean result = validator.isValid("SecureP@ss1", context);
            assertThat(result).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "Password1!",
                "MyP@ssw0rd",
                "Str0ng!Pass",
                "Test#1234",
                "C0mpl3x!Pwd"
        })
        @DisplayName("Should accept various strong passwords")
        void isValid_shouldAcceptVariousStrongPasswords(String password) {
            boolean result = validator.isValid(password, context);
            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Password length tests")
    class PasswordLengthTests {

        @Test
        @DisplayName("Should reject password shorter than 8 characters")
        void isValid_shouldRejectShortPassword() {
            boolean result = validator.isValid("Sh0rt!", context);
            assertThat(result).isFalse();
            verify(context).buildConstraintViolationWithTemplate("Password must be at least 8 characters");
        }

        @Test
        @DisplayName("Should accept password with exactly 8 characters")
        void isValid_shouldAcceptExactly8Characters() {
            boolean result = validator.isValid("Passw0r!", context);
            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Uppercase letter tests")
    class UppercaseTests {

        @Test
        @DisplayName("Should reject password without uppercase letter")
        void isValid_shouldRejectPasswordWithoutUppercase() {
            boolean result = validator.isValid("password1!", context);
            assertThat(result).isFalse();
            verify(context).buildConstraintViolationWithTemplate("Password must contain at least one uppercase letter");
        }
    }

    @Nested
    @DisplayName("Lowercase letter tests")
    class LowercaseTests {

        @Test
        @DisplayName("Should reject password without lowercase letter")
        void isValid_shouldRejectPasswordWithoutLowercase() {
            boolean result = validator.isValid("PASSWORD1!", context);
            assertThat(result).isFalse();
            verify(context).buildConstraintViolationWithTemplate("Password must contain at least one lowercase letter");
        }
    }

    @Nested
    @DisplayName("Digit tests")
    class DigitTests {

        @Test
        @DisplayName("Should reject password without digit")
        void isValid_shouldRejectPasswordWithoutDigit() {
            boolean result = validator.isValid("Password!", context);
            assertThat(result).isFalse();
            verify(context).buildConstraintViolationWithTemplate("Password must contain at least one digit");
        }
    }

    @Nested
    @DisplayName("Special character tests")
    class SpecialCharacterTests {

        @Test
        @DisplayName("Should reject password without special character")
        void isValid_shouldRejectPasswordWithoutSpecialChar() {
            boolean result = validator.isValid("Password1", context);
            assertThat(result).isFalse();
            verify(context).buildConstraintViolationWithTemplate(
                    "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)");
        }

        @ParameterizedTest
        @ValueSource(strings = {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "-"})
        @DisplayName("Should accept various special characters")
        void isValid_shouldAcceptVariousSpecialCharacters(String specialChar) {
            String password = "Password1" + specialChar;
            boolean result = validator.isValid(password, context);
            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Common password tests")
    class CommonPasswordTests {

        @ParameterizedTest
        @ValueSource(strings = {
                "password123",
                "Password123",
                "qwerty123",
                "admin123",
                "letmein123"
        })
        @DisplayName("Should reject common passwords")
        void isValid_shouldRejectCommonPasswords(String password) {
            boolean result = validator.isValid(password, context);
            assertThat(result).isFalse();
            verify(context).buildConstraintViolationWithTemplate("Password is too common and easily guessable");
        }
    }

    @Nested
    @DisplayName("Null and blank tests")
    class NullAndBlankTests {

        @Test
        @DisplayName("Should reject null password")
        void isValid_shouldRejectNullPassword() {
            boolean result = validator.isValid(null, context);
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject blank password")
        void isValid_shouldRejectBlankPassword() {
            boolean result = validator.isValid("   ", context);
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject empty password")
        void isValid_shouldRejectEmptyPassword() {
            boolean result = validator.isValid("", context);
            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("Multiple violation tests")
    class MultipleViolationTests {

        @Test
        @DisplayName("Should report all violations for very weak password")
        void isValid_shouldReportAllViolationsForWeakPassword() {
            boolean result = validator.isValid("abc", context);
            assertThat(result).isFalse();
            
            verify(context, atLeast(4)).buildConstraintViolationWithTemplate(anyString());
        }
    }
}
