package com.skillstorm.models;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanVerifier;

import com.skillstorm.authservice.models.JwtValidationDto;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.models.UserDto;
import com.skillstorm.authservice.models.UserLoginDto;

public class DtoAllTests {
    @Test
    public void testAllDtos() {
        BeanVerifier.verifyBeans(JwtValidationDto.class, UserCredentials.class, UserCredentialsDto.class, UserDto.class, UserLoginDto.class);
    }
}
