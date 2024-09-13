package com.skillstorm.models;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.models.UserDto;

public class UserDtoTest {

    private UserDto userDto;
    private Integer id;
    private String email;

    @BeforeEach
    public void setup() {
        id = 1;
        email = "test@email.com";
        userDto = UserDto.builder()
            .id(id)
            .email(email)
            .build();
    }

    // test constructor with no args
    @Test
    public void testEmptyConstructor() {
        userDto = new UserDto();
        assertNotNull(userDto);
    }

    // test constructor with all args
    @Test
    public void testLoadedConstructor() {
        assertEquals(id, userDto.getId());
        assertEquals(email, userDto.getEmail());
    }

    // test toString method
    @Test
    public void testToString() {
        userDto = new UserDto(id, email);
        String expectedString = "UserDto(id=" + id + ", email=" + email + ")";
        assertEquals(expectedString, userDto.toString());
    }
}
