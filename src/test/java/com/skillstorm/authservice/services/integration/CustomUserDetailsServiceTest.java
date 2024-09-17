package com.skillstorm.authservice.services.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;

import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.CustomUserDetailsService;

@SpringBootTest
public class CustomUserDetailsServiceTest {
    
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private UserCredentialsRepository userRepository;

    private String username;

    @BeforeEach
    public void setup() {
        customUserDetailsService = new CustomUserDetailsService(userRepository);
        username = "david.melanson@gmail.com";
    }

    @Test
    public void loadUserByUsernameTest() {
        UserDetails user = customUserDetailsService.loadUserByUsername(username);

        assertEquals(username, user.getUsername());
        assertEquals("$2y$10$SfJCRbSkbM.ObOJHvVCRNuxdrY13loabTM8ROaGW1kBCWJHhI/iZ6", user.getPassword());
        assertEquals("[USER]", user.getAuthorities().toString());
    }
}
