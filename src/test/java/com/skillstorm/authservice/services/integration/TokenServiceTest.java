package com.skillstorm.authservice.services.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.TokenService;

@SpringBootTest
public class TokenServiceTest {

    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private UserCredentialsRepository userCredentialsRepository;

    private String username;
    private String password;
    private Authentication auth;

    @BeforeEach
    public void setup() {
        tokenService = new TokenService(jwtEncoder, jwtDecoder, userCredentialsRepository);
        username = "joseph.sam@gmail.com";
        password = "$2y$10$R.AVbuzy7f7Vijnj94DF1.7aI8C7V4Zwbf2FWAWk2dCRC3n1iOkbG";
        auth = new UsernamePasswordAuthenticationToken(username, password);
    }

    @Test
    public void generateJwt() {
        String jwt = tokenService.generateJwt(auth, username);
        assertNotNull(jwt);
    }

    @Test
    public void decodeJwtTest() {
        String jwt = tokenService.generateJwt(auth, username);
        String userId = tokenService.decodeJwt(jwt);
        assertEquals("1", userId);
    }

}
