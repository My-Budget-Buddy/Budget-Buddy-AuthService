package com.skillstorm.controllers.integration;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import org.mockito.Mockito;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.skillstorm.authservice.AuthServiceRunner;
import com.skillstorm.authservice.services.AuthService;

import jakarta.transaction.Transactional;

@SpringBootTest(
    classes = AuthServiceRunner.class,
    properties = {
        "eureka.client.enabled=false",
        "spring.cloud.discovery.enabled=false",
        "spring.cloud.config.enabled=false"
    }
)
@AutoConfigureMockMvc
@Transactional // Rollback the changes after each test
public class AuthControllerMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @SpyBean
    private AuthService authService;

    private final String newUser = "newuser@gmail.com";
    private final String newPassword = "newpassword";

    @BeforeEach
    public void setUp() {
        // Mock methods in AuthService that interact with User Service
        Mockito.doReturn(true).when(authService).checkForUserServiceInstance();
        Mockito.doNothing().when(authService).createUserInUserService(Mockito.anyInt(), Mockito.anyString());
    }

    @Test
    @Order(1)
    public void testRegisterUserSuccess() throws Exception {
        // Simulate a POST request to /auth/register with a JSON object containing a username and password
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/register")
            .contentType("application/json")
            .content("{\"username\":\"" + newUser + "\",\"password\":\"" + newPassword + "\"}"))
            .andExpect(status().isCreated());
    }

    @Test
    @Order(2)
    public void testLoginUserSuccess() throws Exception {
        // First, register the user
        testRegisterUserSuccess();

        // Simulate a POST request to /auth/login with a JSON object containing the newly registered username and password
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/login")
            .contentType("application/json")
            .content("{\"username\":\"" + newUser + "\",\"password\":\"" + newPassword + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value(newUser));
    }
}
