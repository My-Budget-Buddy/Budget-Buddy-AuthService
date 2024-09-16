package com.skillstorm.controllers.integration;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import org.mockito.Mockito;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.jayway.jsonpath.JsonPath;

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
        // Simulate a POST request to /auth/register with a Json object containing a username and password
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

        // Simulate a POST request to /auth/login with a Json object containing registered username and password
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/login")
            .contentType("application/json")
            .content("{\"username\":\"" + newUser + "\",\"password\":\"" + newPassword + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value(newUser));
    }

    @Test
    @Order(3)
    public void testUpdatePasswordSuccess() throws Exception {
        // First, register the user
        testRegisterUserSuccess();

        // Update the password
        // user().roles("USER") - simulate valid user
        String updatedPassword = "updatedpassword";
        mockMvc.perform(MockMvcRequestBuilders.put("/auth/update/password")
            .contentType("application/json")
            .content("{\"username\":\"" + newUser + "\",\"password\":\"" + updatedPassword + "\"}")
            .with(user(newUser).roles("USER")))
            .andExpect(status().isOk())
            .andExpect(content().string("Password updated!"));

        // Try logging in with the new password
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/login")
            .contentType("application/json")
            .content("{\"username\":\"" + newUser + "\",\"password\":\"" + updatedPassword + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value(newUser));
    }

    @Test
    @Order(4)
    public void testLogoutRedirect() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/auth/logout/redirect"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("https://frontend.skillstorm-congo.com/"));
    }

    @Test
    @Order(5)
    public void testValidateJwtSuccess() throws Exception {
        // First, register and login to get the JWT
        testRegisterUserSuccess();

        // Login to get the JWT
        MvcResult loginResult = mockMvc.perform(MockMvcRequestBuilders.post("/auth/login")
            .contentType("application/json")
            .content("{\"username\":\"" + newUser + "\",\"password\":\"" + newPassword + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value(newUser))
            .andReturn();

        // Extract JWT from response
        String responseContent = loginResult.getResponse().getContentAsString();
        String jwt = JsonPath.parse(responseContent).read("$.jwt");

        // Mock the tokenService.decodeJwt method to return a fake userId
        Mockito.doReturn("fakeUserId").when(authService).getJwtClaim(Mockito.anyString());

        // Now, perform validate endpoint
        mockMvc.perform(MockMvcRequestBuilders.get("/auth/validate")
            .header("Authorization", "Bearer " + jwt))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.jwtSubject").value(newUser))
            .andExpect(jsonPath("$.jwtClaim").value("fakeUserId"));
    }
}
