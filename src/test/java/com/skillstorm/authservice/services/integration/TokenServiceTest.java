package com.skillstorm.authservice.services.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileReader;
import java.io.IOException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.util.FileCopyUtils;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.skillstorm.authservice.AuthServiceRunner;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.TokenService;

@SpringBootTest(
    classes = AuthServiceRunner.class,
    properties = {
        "eureka.client.enabled=false",
        "spring.cloud.discovery.enabled=false",
        "spring.cloud.config.enabled=false"
    }
)
public class TokenServiceTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private UserCredentialsRepository userCredentialsRepository;

    @Autowired
    private ResourceLoader resourceLoader;

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

    @AfterEach
    public void tearDown() throws IOException {
        Resource resource = resourceLoader.getResource("classpath:resetDB.sql");
        jdbcTemplate.execute(FileCopyUtils.copyToString(new FileReader(resource.getFile())));
    }

    @Test
    public void generateJwt() {
        // generate a jwt token
        String jwt = tokenService.generateJwt(auth, username);
        // ensure token is not null
        assertNotNull(jwt);
    }

    @Test
    public void decodeJwtTest() {
        // generate a jwt token to decode
        String jwt = tokenService.generateJwt(auth, username);
        // decode the jwt token
        String userId = tokenService.decodeJwt(jwt);
        // verify the userId returned is with correct Id
        assertEquals("1", userId);
    }

}
