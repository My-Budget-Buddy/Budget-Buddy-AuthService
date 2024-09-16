package com.skillstorm.services;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestBodySpec;
import org.springframework.web.client.RestClient.RequestBodyUriSpec;
import org.springframework.web.client.RestClient.ResponseSpec;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.AuthService;
import com.skillstorm.authservice.services.TokenService;

import jakarta.servlet.http.HttpServletResponse;

public class AuthServiceTest {

    @Mock
    private UserCredentialsRepository userCredentialsRepo;

    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private AuthenticationManager authManager;

    @Mock
    private TokenService tokenService;

    @Mock
    private LoadBalancerClient loadBalancerClient;

    @Mock
    private HttpServletResponse httpServletResponse;

    private String username;
    private String password;

    @InjectMocks
    private AuthService authService;

    private AutoCloseable closeable;

    @BeforeEach
    public void setup() {
        closeable = MockitoAnnotations.openMocks(this);
        username = "user";
        password = "secret";
    }

    @AfterEach
    public void teardown() throws Exception {
        closeable.close();
    }

    @Test
    public void testLoadedConstructor() {
        authService = new AuthService(
            userCredentialsRepo, 
            passwordEncoder, 
            authManager, 
            tokenService, 
            loadBalancerClient);
    }

    /**
     * when register gets called
     *  1. checks if username exists
     *  2. encodes the password and creats usercreds
     *  3. checks if user service instance is available
     *      a. tells loadbalancerclient to choose "user-service" service instance -> this looks up all instances of matching "user-service" from service discovery
     *  4. save the new user credentials
     *  5. calls createuserservice -> which uses the saved user id and username
     *      a. chooses the service instance
     *      b. builds a userdto
     *      c. construct the serviceurl
     *      d. sets post request to the service url and fetches the response
     *      e. 
     * @throws UserExistsException 
     */

    @Test
    public void testRegister() throws UserExistsException {
        // stub repo method to not find the username
        when(userCredentialsRepo.existsByUsername(anyString()))
        .thenReturn(false);

        // create authservice spy to stub checkForUserServiceInstance to return true when called
        AuthService authServiceSpy = spy(authService);
        when(authServiceSpy.checkForUserServiceInstance()).thenReturn(true);

        UserCredentials newUser = UserCredentials.builder()
            .id(1)
            .username(username)
            .password(password)
            .userRole("USER")
            .build();

        // stub repo method to save the new user
        when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(newUser);

        // dont do anything when createUserInUserService is called
        doNothing().when(authServiceSpy).createUserInUserService(newUser.getId(), newUser.getUsername());

        authServiceSpy.register(username, password);

        // verify the user was saved and createUserInUserService was called
        verify(userCredentialsRepo).save(any(UserCredentials.class));
        verify(authServiceSpy).createUserInUserService(newUser.getId(), newUser.getUsername());
    }

    @Test
    public void testRegisterUserExistsException() {
        // stub repo method to find the username
        when(userCredentialsRepo.existsByUsername(anyString()))
        .thenReturn(true);

        // store the exception thrown
        UserExistsException exception = assertThrows(UserExistsException.class, () -> {
            authService.register(username, password);
        });

        // verify the exception messages match
        assertEquals("That username is not available.", exception.getMessage());
    }

    @Test
    public void testRegisterUserUserServiceInstanceException() {
        // store thrown exception when checkForUserServiceInstance is called with no service instance
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.register(username, password);
        });

        // verify the exception messages match
        assertEquals("Error: User not registered. No instance of user-service available", exception.getMessage());
    }

    @Test
    public void testLogin() throws AuthException{
        String token = "secretToken";
        Authentication auth = new UsernamePasswordAuthenticationToken(username, password);
        UserCredentials foundUser = new UserCredentials();
        foundUser.setUsername(username);

        // stub authenticate to return auth we created earlier
        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(auth);

        // stub findbyusername to return user we created earlier
        when(userCredentialsRepo.findByUsername(username))
        .thenReturn(Optional.ofNullable(foundUser));

        // stub generatejwt to return token created earlier
        when(tokenService.generateJwt(auth, username)).thenReturn(token);

        UserLoginDto userLoginDto = authService.login(username, password, httpServletResponse);

        // verify the username and tokens match
        assertEquals(username, userLoginDto.getUsername());
        assertEquals(token, userLoginDto.getJwt());
    }

    @Test
    public void testLoginException() {
        // force authenticate to throw exception to be caught
        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenThrow(new AuthenticationException("Invalid Credentials"){});

        // store the exception thrown
        AuthException exception = assertThrows(AuthException.class, () -> {
            authService.login(username, password, httpServletResponse);
        });

        // verify the exception messages match
        assertEquals("User not found or bad credentials.", exception.getMessage());
    }

    @Test
    public void testOauth2Login() {
        RedirectView redirectView = mock(RedirectView.class);
        doNothing().when(redirectView).setContextRelative(true);
        
        // mock the OAuth2AuthenticationToken and OAuth2User
        OAuth2AuthenticationToken authToken = mock(OAuth2AuthenticationToken.class);
        OAuth2User oauth2User = mock(OAuth2User.class);
    
        String token = "token";
        String username = "user";
    
        // stub getPrincipal() on authToken to return the OAuth2User
        when(authToken.getPrincipal()).thenReturn(oauth2User);
    
        // stub getAttribute() on oauth2User to return the username
        when(oauth2User.getAttribute(anyString())).thenReturn(username);
    
        AuthService authServiceSpy = spy(authService);
        // stub findOrCreateUser to do nothing
        doNothing().when(authServiceSpy).findOrCreateUser(anyString());
    
        // stub generateJwt to return the token
        when(tokenService.generateJwt(any(Authentication.class), anyString())).thenReturn(token);
    
        // store the response from oauth2Login
        RedirectView response = authServiceSpy.oauth2Login(authToken, httpServletResponse);
    
        // verify the url is set to the frontend url
        assertEquals("https://frontend.skillstorm-congo.com/", response.getUrl());
    }

    @Test
    public void testOauth2LoginException() {
        // mock the OAuth2AuthenticationToken and OAuth2User
        Authentication auth = new UsernamePasswordAuthenticationToken(username, password);
        OAuth2AuthenticationToken authToken = mock(OAuth2AuthenticationToken.class);

        OAuth2User oauth2User = mock(OAuth2User.class);
        // stub getPrincipal() on authToken to return the OAuth2User
        when(authToken.getPrincipal()).thenReturn(oauth2User);
        // stub getAttribute() on oauth2User to return null
        when(oauth2User.getAttribute(anyString())).thenReturn(null);

        // verify exception was thrown
        assertThrows(Exception.class, () -> {
            authService.oauth2Login(auth, httpServletResponse);
        });
    }

    @Test
    public void testUpdatePassword() {
        UserCredentials user = new UserCredentials();
        user.setPassword(password);

        // stub findbyusername to return user we created earlier
        when(userCredentialsRepo.findByUsername(anyString()))
        .thenReturn(Optional.ofNullable(user));

        // stub save to return the user we created earlier
        when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(user);

        String response = authService.updatePassword(username, password);

        // verify the response matches
        assertEquals("Password updated!", response);
    }

    @Test
    public void testUpdatePasswordInvalid() {
        // stub findbyusername to return empty to throw exception
        when(userCredentialsRepo.findByUsername(anyString()))
        .thenReturn(Optional.empty());

        String response = authService.updatePassword(username, password);

        // verify the response matches
        assertEquals("User not found", response);
    }

    @Test
    public void testFindOrCreateUser() {
        // stub findbyusername to return empty to create a new user
        when(userCredentialsRepo.findByUsername(anyString()))
        .thenReturn(Optional.empty());

        UserCredentials user = UserCredentials.builder()
            .id(1)
            .username(username)
            .oauth2Idp(password)
            .userRole("USER")
            .build();
        
        // stub save to return the user we created earlier
        when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(user);

        AuthService authServiceSpy = spy(authService);
        // stub createuserinservice to do nothing
        doNothing().when(authServiceSpy).createUserInUserService(user.getId(), user.getUsername());

        authServiceSpy.findOrCreateUser(username);

        // verify the user was saved and createUserInUserService was called
        verify(userCredentialsRepo).save(any(UserCredentials.class));
        verify(authServiceSpy).createUserInUserService(user.getId(), user.getUsername());
    }

    @Test
    public void testFindOrCreateUserInvalid() {
        // stub repo method to return user not found
        when(userCredentialsRepo.findByUsername(anyString())).thenReturn(Optional.ofNullable(new UserCredentials()));

        authService.findOrCreateUser(username);

        // verify repo method was called
        verify(userCredentialsRepo).findByUsername(username);
    }

    @Test
    public void testGetJwtClaim() {
        String token = "token";

        // stub decodeJwt to return the token
        when(tokenService.decodeJwt(anyString())).thenReturn(token);

        String newToken = authService.getJwtClaim(token);

        // verify the tokens match
        assertEquals(token, newToken);
    }

    @Test
    public void testCheckForUserServiceInstance() {
        // mock the ServiceInstance
        ServiceInstance instance = mock(ServiceInstance.class);

        // stub choose to return the instance
        when(loadBalancerClient.choose(anyString())).thenReturn(instance);

        boolean response = authService.checkForUserServiceInstance();

        // verify the response is true
        assertTrue(response);
    }

    @Test
    public void testCheckForUserServiceInstanceInvalid() {
        // stub choose to return null
        when(loadBalancerClient.choose(anyString())).thenReturn(null);

        boolean response = authService.checkForUserServiceInstance();

        // verify the response is false
        assertFalse(response);
    }

    @Test
    public void testCreateUserInUserService() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        String serviceUrl = "http://test.com/users";
        ServiceInstance instance = mock(ServiceInstance.class);

        // stub choose to return the instance
        when(loadBalancerClient.choose(anyString())).thenReturn(instance);
        // stub getUri to return the service url
        when(instance.getUri()).thenReturn(URI.create(serviceUrl));

        // mock RestClient, requests, and response
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

        // call the method
        authService.createUserInUserService(1, "email");

        // verify the methods were called
        assertEquals(serviceUrl, instance.getUri().toString());
        verify(loadBalancerClient).choose("user-service");
        verify(restClient).post();
    }

    @Test
    public void testCreateUserInUserServiceIllegalStateException() {
        // stub choose to return null to throw exception
        when(loadBalancerClient.choose(anyString())).thenReturn(null);

        // store the exception thrown
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            authService.createUserInUserService(1, "test@email.com");
        });

        // verify the exception messages match
        assertEquals("No user-service instance available", exception.getMessage());
    }

    @Test
    public void testCreateUserInUserServiceRuntimeException() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        String serviceUrl = "http://test.com/users";
        ServiceInstance instance = mock(ServiceInstance.class);

        when(loadBalancerClient.choose(anyString())).thenReturn(instance);
        when(instance.getUri()).thenReturn(URI.create(serviceUrl));

        // mock RestClient, requests, and response
        RestClient restClient = mock(RestClient.class);
        RequestBodyUriSpec requestBodyUriSpec = mock(RequestBodyUriSpec.class);
        RequestBodySpec requestBodySpec = mock(RequestBodySpec.class);

        // set the restClient field to the mock
        Field restClientField = AuthService.class.getDeclaredField("restClient");
        restClientField.setAccessible(true);
        restClientField.set(authService, restClient);

        // stub post, uri, contentType, body, and retrieve to throw exception for bad request
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(UserDto.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        // store the exception thrown
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.createUserInUserService(1, serviceUrl);
        });

        // verify the exception bad request status
        assertEquals(HttpStatus.BAD_REQUEST.toString(), exception.getMessage());
    }
}
