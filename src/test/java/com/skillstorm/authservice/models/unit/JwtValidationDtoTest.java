package com.skillstorm.authservice.models.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.skillstorm.authservice.models.JwtValidationDto;

public class JwtValidationDtoTest {
    
    private JwtValidationDto jwtValidationDto;
    private String jwtSubject;
    private String jwtClaim;

    @BeforeEach
    public void setup() {
        jwtSubject = "jWebTokenSubject";
        jwtClaim = "jWebTokenClaim";
        jwtValidationDto = JwtValidationDto.builder()
            .jwtSubject(jwtSubject)
            .jwtClaim(jwtClaim)
            .build();
    }

    // test constructor with no args
    @Test
    public void testEmptyConstructor() {
        jwtValidationDto = new JwtValidationDto();
        assertNotNull(jwtValidationDto);
    }

    // test constructor with all args
    @Test
    public void testLoadedConstructor() {
        assertEquals(jwtSubject, jwtValidationDto.getJwtSubject());
        assertEquals(jwtClaim, jwtValidationDto.getJwtClaim());
    }

    // test toString method
    @Test
    public void testToString() {
        jwtValidationDto = new JwtValidationDto(jwtSubject, jwtClaim);
        String expectedString = "JwtValidationDto(jwtSubject=" + jwtSubject + ", jwtClaim=" + jwtClaim + ")";
        assertEquals(expectedString, jwtValidationDto.toString());
    }
}
