package com.skillstorm.authservice.models.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.models.UserCredentialsDto;

public class UserCredentialsDtoTest {
    
    private UserCredentialsDto userCredentialsDto;
    private String username;
    private String password;

    @BeforeEach
    public void setup() {
        username = "user";
        password = "secret";
        userCredentialsDto = UserCredentialsDto.builder()
            .username(username)
            .password(password)
            .build();
    }

    // test constructor with no args
    @Test
    public void testEmptyConstructor() {
        userCredentialsDto = new UserCredentialsDto();
        assertNotNull(userCredentialsDto);
    }

    // test constructor with all args
    @Test
    public void testLoadedConstructor() {
        assertEquals(username, userCredentialsDto.getUsername());
        assertEquals(password, userCredentialsDto.getPassword());
    }

    // test toString method
    @Test
    public void testToString() {
        userCredentialsDto = new UserCredentialsDto(username, password);
        String expectedString = "UserCredentialsDto(username=" + username + ", password=" + password + ")";
        assertEquals(expectedString, userCredentialsDto.toString());
    }
}
