package com.skillstorm.authservice.services.integration;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.RestClient;

import com.skillstorm.authservice.AuthServiceRunner;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.AuthService;
import com.skillstorm.authservice.services.TokenService;

@SpringBootTest(
    classes = AuthServiceRunner.class,
    properties = {
        "eureka.client.enabled=false",
        "spring.cloud.discovery.enabled=false",
        "spring.cloud.config.enabled=false"
    }
)
public class AuthServiceTest {
    
    @Autowired
    private AuthService authService;

    @Autowired
    private UserCredentialsRepository userCredentialsRepo;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private AuthenticationManager authManager;

    @MockBean
    private TokenService tokenService;

    @MockBean
    private LoadBalancerClient loadBalancerClient;

    private String username;
    private String password;

    // @BeforeEach
    // public void setup() {
    //     authService = new AuthService(userCredentialsRepo, passwordEncoder, authManager, tokenService, loadBalancerClient);
    //     username = "user";
    //     password = "secret";
    // }

    // @Test
    // public void registerTest() throws UserExistsException, URISyntaxException {
    //     String uri = "http://localhost:8888";

    //     ServiceInstance instance = mock(ServiceInstance.class);
    //     when(loadBalancerClient.choose(anyString())).thenReturn(instance);
    //     when(instance.getUri()).thenReturn(new URI(uri));

    //     authService.register(username, password);

    // }
}
