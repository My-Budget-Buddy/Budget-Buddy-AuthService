package com.skillstorm.authservice.exceptions.unit;

import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.exceptions.AuthException;

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
