package com.skillstorm.authservice.services.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.FileReader;
import java.io.IOException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.FileCopyUtils;

import com.skillstorm.authservice.AuthServiceRunner;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.CustomUserDetailsService;

@SpringBootTest(
    classes = AuthServiceRunner.class,
    properties = {
        "eureka.client.enabled=false",
        "spring.cloud.discovery.enabled=false",
        "spring.cloud.config.enabled=false"
    }
)
public class CustomUserDetailsServiceTest {
    
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private UserCredentialsRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ResourceLoader resourceLoader;

    private String username;

    @BeforeEach
    public void setup() {
        customUserDetailsService = new CustomUserDetailsService(userRepository);
        username = "david.melanson@gmail.com";
    }

    @AfterEach
    public void tearDown() throws IOException {
        Resource resource = resourceLoader.getResource("classpath:resetDB.sql");
        jdbcTemplate.execute(FileCopyUtils.copyToString(new FileReader(resource.getFile())));
    }

    @Test
    public void loadUserByUsernameTest() {
        UserDetails user = customUserDetailsService.loadUserByUsername(username);

        // verify user details are correct
        assertEquals(username, user.getUsername());
        assertEquals("$2y$10$SfJCRbSkbM.ObOJHvVCRNuxdrY13loabTM8ROaGW1kBCWJHhI/iZ6", user.getPassword());
        assertEquals("[USER]", user.getAuthorities().toString());
    }
}
