package com.skillstorm.authservice.exceptions.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.exceptions.UserExistsException;

public class UserExistsExceptionTests {
    
    @Test
    void testUserExistsExceptionMessage() {
        String errorMessage = "User already exists";
        UserExistsException exception = assertThrows(UserExistsException.class, () -> {
            throw new UserExistsException(errorMessage);
        });

        assertEquals(errorMessage, exception.getMessage());
    }
}
