package com.skillstorm.authservice.models.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.models.UserLoginDto;

public class UserLoginDtoTest {
    
    private UserLoginDto userLoginDto;
    private String username;
    private String jwt;

    @BeforeEach
    public void setup() {
        username = "user";
        jwt = "jwebtoken";
        userLoginDto = UserLoginDto.builder()
            .username(username)
            .jwt(jwt)
            .build();
    }

    // test constructor with no args
    @Test
    public void testEmptyConstructor() {
        userLoginDto = new UserLoginDto();
        assertNotNull(userLoginDto);
    }

    // test constructor with all args
    @Test
    public void testLoadedConstructor() {
        assertEquals(username, userLoginDto.getUsername());
        assertEquals(jwt, userLoginDto.getJwt());
    }

    // test toString method
    @Test
    public void testToString() {
        String expectedString = "UserLoginDto(username=" + username + ", jwt=" + jwt + ")";
        assertEquals(expectedString, userLoginDto.toString());
    }
}
