package com.skillstorm.authservice.exceptions;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthExceptionTests {

    @Test
    void testAuthExceptionMessage() {
        String errorMessage = "Authentication failed";
        AuthException exception = assertThrows(AuthException.class, () -> {
            throw new AuthException(errorMessage);
        });

        assertEquals(errorMessage, exception.getMessage());
    }
}
