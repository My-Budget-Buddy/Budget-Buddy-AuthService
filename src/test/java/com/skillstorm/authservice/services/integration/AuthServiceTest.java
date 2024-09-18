package com.skillstorm.authservice.services.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.NoSuchElementException;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestBodySpec;
import org.springframework.web.client.RestClient.RequestBodyUriSpec;
import org.springframework.web.client.RestClient.ResponseSpec;

import com.skillstorm.authservice.AuthServiceRunner;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.AuthService;
import com.skillstorm.authservice.services.TokenService;

import jakarta.servlet.http.HttpServletResponse;

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

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ResourceLoader resourceLoader;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private AuthenticationManager authManager;

    @Autowired
    private TokenService tokenService;

    @MockBean
    private LoadBalancerClient loadBalancerClient;

    @MockBean
    private HttpServletResponse httpServletResponse;

    @BeforeEach
    public void setup() {
        authService = new AuthService(userCredentialsRepo, passwordEncoder, authManager, tokenService, loadBalancerClient);
    }

    @AfterEach
    public void tearDown() throws IOException {
        Resource resource = resourceLoader.getResource("classpath:resetDB.sql");
        jdbcTemplate.execute(FileCopyUtils.copyToString(new FileReader(resource.getFile())));
    }

    /**
     * helper method to create mocks for service instance, load balancer client, mock rest client injection and post request
     * used in any method that calls createUserInUserService
     * @exception NoSuchFieldException
     * @exception SecurityException
     * @exception IllegalAccessException
     */
    public void createUserHelper() throws NoSuchFieldException, SecurityException, IllegalAccessException {
        String uri = "http://localhost:8888";
        // mock this to bypass checkForUserServiceInstance in authservice
        ServiceInstance instance = mock(ServiceInstance.class);
        when(loadBalancerClient.choose(anyString())).thenReturn(instance);
        when(instance.getUri()).thenReturn(URI.create(uri));

        RestClient restClient = mock(RestClient.class);
        RequestBodyUriSpec requestBodyUriSpec = mock(RequestBodyUriSpec.class);
        RequestBodySpec requestBodySpec = mock(RequestBodySpec.class);
        ResponseSpec responseSpec = mock(ResponseSpec.class);

        // set the restClient field to the mock
        Field restClientField = AuthService.class.getDeclaredField("restClient");
        restClientField.setAccessible(true);
        restClientField.set(authService, restClient);

        // stub post, uri, contentType, body, and retrieve to return the response
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(UserDto.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(any(ParameterizedTypeReference.class))).thenReturn(null);

    }

    /* Testing register */

    @Test
    public void registerTest() throws NoSuchFieldException, SecurityException, IllegalAccessException, UserExistsException  {
        String encodedPassword = "encodedTestSecret";
        String username = "testUser";
        String password = "testSecret";

        when(passwordEncoder.encode(password)).thenReturn(encodedPassword);

        createUserHelper();
        
        authService.register(username, password);

        // verify that the user was created in the user-service
        assertTrue(userCredentialsRepo.existsByUsername(username));

        // store the user in a variable to check the values
        Optional<UserCredentials> user = userCredentialsRepo.findByUsername(username);

        // not null check for assurance
        assertNotNull(user);

        // verify that the user was created with correct username
        assertEquals(username, user.get().getUsername());
        // verify that the password was encoded
        assertEquals(encodedPassword, user.get().getPassword());
    }

    @Test
    public void registerUserExistsExceptionTest() {
        // plugin user that exists into repo method to throw exception
        String username = "joseph.sam@gmail.com";
        String password = "$2y$10$R.AVbuzy7f7Vijnj94DF1.7aI8C7V4Zwbf2FWAWk2dCRC3n1iOkbG";

        UserExistsException exception = assertThrows(UserExistsException.class, () -> {
            authService.register(username, password);
        });

        assertEquals("That username is not available.", exception.getMessage());
    }

    @Test
    public void registerRuntimeException() {
        String username = "testUser";
        String password = "testSecret";

        // mock this to bypass checkForUserServiceInstance in authservice
        when(loadBalancerClient.choose(anyString())).thenReturn(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.register(username, password);
        });

        assertEquals("Error: User not registered. No instance of user-service available", exception.getMessage());
    }

    /* Testing login */

    @Test
    public void loginTest() throws AuthException {
        // use existing credentials
        String username = "joseph.sam@gmail.com";
        String password = "$2y$10$R.AVbuzy7f7Vijnj94DF1.7aI8C7V4Zwbf2FWAWk2dCRC3n1iOkbG";
        
        Authentication auth = new UsernamePasswordAuthenticationToken(username, password);
        when(authManager.authenticate(any(Authentication.class))).thenReturn(auth);

        UserLoginDto userLoginDto = authService.login(username, password, httpServletResponse);

        // verify that the userLoginDto is not null
        assertNotNull(userLoginDto);
        // verify that the username and jwt are correct
        assertEquals(userLoginDto.getUsername(), username);
        assertEquals(userLoginDto.getJwt(), tokenService.generateJwt(auth, username));
    }

    @Test
    public void loginAuthExceptionTest() {
        String username = "testUser";
        String password = "testSecret";
        // stub to throw authentication exception
        when(authManager.authenticate(any(Authentication.class)))
        .thenThrow(mock(AuthenticationException.class));

        AuthException exception = assertThrows(AuthException.class, () -> {
            authService.login(username, password, httpServletResponse);
        });

        // verify exception is thrown with correct message
        assertEquals("User not found or bad credentials.", exception.getMessage());
    }

    @Test
    public void loginNoSuchElementExceptionTest() {
        String username = "testUser";
        String password = "testSecret";

        // use non-existing credentials to throw exception
        NoSuchElementException exception = assertThrows(NoSuchElementException.class, () -> {
            authService.login(username, password, httpServletResponse);
        });

        // verify exception is not null with correct message
        assertNotNull(exception);
    }

    /* Testing updatePassword */

    @Test
    public void updatePasswordTest() {
        String username = "joseph.sam@gmail.com";
        String password = "newPassword";
        String encodedPassword = "encodedNewPassword";

        when(passwordEncoder.encode(password)).thenReturn(encodedPassword);

        String response = authService.updatePassword(username, password);

        // ensure correct response for succesfull password update
        assertEquals("Password updated!", response);

        Optional<UserCredentials> user = userCredentialsRepo.findByUsername(username);

        // verify correct user's password was updated
        assertEquals(username, user.get().getUsername());
        assertEquals(encodedPassword, user.get().getPassword());
    }

    @Test
    public void updatePasswordNullUsernameTest() {
        String username = null;
        String password = "testPassword";
        // use null password to verify that null is returned
        String response = authService.updatePassword(username, password);

        // verify that null is returned
        assertEquals(response, "User not found");
    }

    @Test
    public void updatePasswordUserNotFoundTest() {
        // use non-existing user to throw exception
        String username = "testUser";

        Optional<UserCredentials> user = userCredentialsRepo.findByUsername(username);
        
        // verify that the user is not found
        assertEquals(Optional.empty(), user);
    }

    // @Test
    // public void updatePasswordExceptionTest() {
    //     RuntimeException exception = assertThrows(RuntimeException.class, () -> {
    //         authService.updatePassword(username, password);
    //     });

    //     assertEquals("Error: User not found. No instance of user-service available", exception.getMessage());
    // }

    /* Testing findOrCreateUserTest */

    @Test
    public void findOrCreateUserTest() throws NoSuchFieldException, SecurityException, IllegalAccessException {
        // use non-existing user to create user
        String username = "testUser";

        createUserHelper();

        authService.findOrCreateUser(username);

        // verify that the user was created
        assertTrue(userCredentialsRepo.existsByUsername(username));

        Optional<UserCredentials> user = userCredentialsRepo.findByUsername(username);

        // verify user was created with correct values
        assertEquals(user.get().getUsername(), username);
        assertEquals(user.get().getOauth2Idp(), "GOOGLE");
        assertEquals(user.get().getUserRole(), "USER");
    }

    @Test
    public void findOrCreateUserExistingUserTest() throws NoSuchFieldException, SecurityException, IllegalAccessException {
        // use existing user to verify that the user is not created
        String username = "joseph.sam@gmail.com";

        createUserHelper();

        authService.findOrCreateUser(username);
    }

    /* Testing getJwtClaim */

    @Test
    public void getJwtClaimTest() {
        String username = "joseph.sam@gmail.com";
        String password = "$2y$10$R.AVbuzy7f7Vijnj94DF1.7aI8C7V4Zwbf2FWAWk2dCRC3n1iOkbG";

        // encode jwt token for decoding
        String encodedToken = tokenService.generateJwt(new UsernamePasswordAuthenticationToken(username, password), username);
        String jwt = authService.getJwtClaim(encodedToken);

        // verify jwt returns correct userId
        assertEquals("1", jwt);
    }

    @Test
    public void getJwtClaimNullTest() {
        // use null token to verify that null is returned
        Exception exception = assertThrows(Exception.class, () -> {
            authService.getJwtClaim(null);
        });

        // verify that exception throws with correct message for null
        assertEquals("An error occurred while attempting to decode the Jwt: Cannot invoke \"String.indexOf(String)\" because \"s\" is null", exception.getMessage());
    }

    @Test
    public void getJwtClaimBadTokenTest() {
        // use non-existing user to verify exception is thrown
        Exception exception = assertThrows(Exception.class, () -> {
            authService.getJwtClaim("badToken");
        });

        // verify that exception throws with correct message for bad token
        assertEquals("An error occurred while attempting to decode the Jwt: Malformed token", exception.getMessage());
    }
}
