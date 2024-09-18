package com.skillstorm.authservice.exceptions.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.exceptions.UserNotFoundException;

public class UserNotFoundExceptionTests {
    
    @Test
    void testUserExistsExceptionMessage() {
        String errorMessage = "User not found";
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
            throw new UserNotFoundException(errorMessage);
        });

        assertEquals(errorMessage, exception.getMessage());
    }
}
