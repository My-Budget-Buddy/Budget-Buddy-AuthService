package com.skillstorm.authservice.exceptions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class Oauth2ExceptionTests {

    @Test
    void testOauth2ExceptionMessage() {
        String errorMessage = "OAuth2 authentication failed";
        Oauth2Exception exception = assertThrows(Oauth2Exception.class, () -> {
            throw new Oauth2Exception(errorMessage);
        });

        assertEquals(errorMessage, exception.getMessage());
    }
}
