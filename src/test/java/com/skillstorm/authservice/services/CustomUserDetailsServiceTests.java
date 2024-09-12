package com.skillstorm.authservice.services;

import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomUserDetailsServiceTest {

    private UserCredentialsRepository userRepository;
    private CustomUserDetailsService customUserDetailsService;

    @BeforeEach
    void setUp() {
        // Need to mock UserCredentialsRepository
        userRepository = mock(UserCredentialsRepository.class);
        // Give the mocked userRepository to the service to test
        customUserDetailsService = new CustomUserDetailsService(userRepository);
    }

    @Test
    void testLoadUserByUsername_UserFound() {
        // Set up the username and mock the repository to return a UserCredentials object
        String username = "testUser";
        UserCredentials userCredentials = mock(UserCredentials.class);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(userCredentials));
        when(userCredentials.getUsername()).thenReturn(username);
        when(userCredentials.getPassword()).thenReturn("password");

        UserDetails result = customUserDetailsService.loadUserByUsername(username);

        // Check that the service returns the UserCredentials object
        assertEquals(userCredentials, result);
        verify(userRepository, times(1)).findByUsername(username);
    }

    @Test
    void testLoadUserByUsername_UserNotFound() {
        // Using non-existent username
        String username = "nonExistentUser";
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        // Check service throws UsernameNotFoundException when the user is not found
        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(username);
        });
        verify(userRepository, times(1)).findByUsername(username);
    }
}
