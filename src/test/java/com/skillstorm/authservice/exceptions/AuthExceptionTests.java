package com.skillstorm.authservice.exceptions;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthExceptionTests {

    @Test
    void testAuthExceptionMessage() {
        // Test that the exception message is set correctly
        String errorMessage = "Authentication failed";
        AuthException exception = assertThrows(AuthException.class, () -> {
            throw new AuthException(errorMessage);
        });

        assertEquals(errorMessage, exception.getMessage());
    }
}
