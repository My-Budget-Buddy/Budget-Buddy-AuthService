package com.skillstorm.authservice;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

//@SpringBootTest
//class AuthServiceRunnerTests {
//
//    @MockBean
//    private ClientRegistrationRepository clientRegistrationRepository;
//
//    @Test
//    void contextLoads() {
//        // Checking Spring context loads
//    }
//
//    @Test
//    void testMain() {
//        // Mock the SpringApplication.run method to return null
//        try (MockedStatic<SpringApplication> mockedSpringApplication = Mockito.mockStatic(SpringApplication.class)) {
//            mockedSpringApplication.when(() -> SpringApplication.run(AuthServiceRunner.class, new String[]{})).thenReturn(null);
//
//            // Call the main method w/ empty arg, which should call SpringApplication
//            AuthServiceRunner.main(new String[]{});
//
//            // Verify that SpringApplication.run was called
//            mockedSpringApplication.verify(() -> SpringApplication.run(AuthServiceRunner.class, new String[]{}));
//        }
//    }
//}