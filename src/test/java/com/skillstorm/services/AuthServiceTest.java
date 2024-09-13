package com.skillstorm.services;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Map;

import org.glassfish.jaxb.core.annotation.OverrideAnnotationOf;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.elasticsearch.ElasticsearchProperties.Restclient;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.ctc.wstx.shaded.msv_core.util.Uri;
import com.google.common.util.concurrent.Service;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.exceptions.UserNotFoundException;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.AuthService;
import com.skillstorm.authservice.services.TokenService;
import com.skillstorm.authservice.utils.enums.Oauth2AuthorizationServer;
import com.skillstorm.authservice.utils.enums.UserRole;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@AutoConfigureMockMvc
public class AuthServiceTest {

    @Autowired
    private MockMvc mockMvc;

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
    private RestClient restClient;

    @Mock
    private RedirectView redirectView;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private RestClient.RequestBodyUriSpec requestBodyUriSpec;

    @Mock
    private RestClient.RequestBodySpec requestBodySpec;

    private String username;
    private String password;

    @InjectMocks
    private AuthService authService;

    private class TestServiceInstance implements ServiceInstance {

        @Override
        public String getServiceId() {
            throw new UnsupportedOperationException("Unimplemented method 'getServiceId'");
        }

        @Override
        public String getHost() {
            throw new UnsupportedOperationException("Unimplemented method 'getHost'");
        }

        @Override
        public int getPort() {
            throw new UnsupportedOperationException("Unimplemented method 'getPort'");
        }

        @Override
        public boolean isSecure() {
            throw new UnsupportedOperationException("Unimplemented method 'isSecure'");
        }

        @Override
        public URI getUri() {
            try {
                URI uri = new URI("http://localhost:8083");
                return uri;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        @Override
        public Map<String, String> getMetadata() {
            throw new UnsupportedOperationException("Unimplemented method 'getMetadata'");
        }

    }

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
     */
    @Test
    public void testRegister() {

    }


    @Test
    public void testRegisterUserExistsInvalid() {
        when(userCredentialsRepo.existsByUsername(anyString()))
        .thenReturn(true);

        UserExistsException exception = assertThrows(UserExistsException.class, () -> {
            authService.register(username, password);
        });

        assertEquals("That username is not available.", exception.getMessage());
    }

    @Test
    public void testRegisterUserUserServiceInstanceInvalid() {
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.register(username, password);
        });

        assertEquals("Error: User not registered. No instance of user-service available", exception.getMessage());
    }

    // @Test
    // public void testRegister() throws Exception {
    //     String encodedPassword = "encodedSecret";

    //     when(userCredentialsRepo.existsByUsername(anyString()))
    //     .thenReturn(false);

    //     // // stub encoder to return predefined encoded password
    //     // when(passwordEncoder.encode(password))
    //     // .thenReturn(encodedPassword);

    //     UserCredentials newUser = UserCredentials.builder()
    //         .id(1)
    //         .username(username)
    //         .password(encodedPassword)
    //         .userRole("USER")
    //         .build();

    //     when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(newUser);

    //     // ServiceInstance instance = mock(ServiceInstance.class);
    //     // when(loadBalancerClient.choose("user-service")).thenReturn(instance);
    //     // when(instance.getUri()).thenReturn(new URI("http://localhost:8080"));

    //     // AuthService authServiceSpy = spy(authService);
    //     // // // doNothing().when(authServiceSpy.checkForUserServiceInstance());
    //     // when(loadBalancerClient.choose(anyString())).thenReturn(any(ServiceInstance.class));
    //     // doReturn(true).when(authServiceSpy).checkForUserServiceInstance();

    //     // authService.checkForUserServiceInstance();

    // //     // // stub saving the new user

    // //     // when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(newUser);

    //     authService.register(username, password);
    // }
    // @Test
    // public void testOauth2Login() {
    //     doNothing().when(redirectView).setContextRelative(true);

    //     // AuthService authServiceSpy = spy(authService);
    //     // doNothing().when(authServiceSpy).findOrCreateUser(username);

    //     RedirectView response = authService.oauth2Login(null, null);
    // }

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
    public void testLoginInvalid() {
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

    // @Test
    // public void testOauth2Login() {
    //     // String redirectUrl = "https://redirect-test-url.com/";
    //     // RedirectView redirectView = new RedirectView(redirectUrl);
    //     OAuth2AuthenticationToken auth = (OAuth2AuthenticationToken) new Authentication();
    //     String username = "test@example.com";
    //     String token = "mock-jwt-token";



    //     // Act
    //     RedirectView result = authService.oauth2Login(auth, httpServletResponse);

    //     // Assert
    //     assertEquals("https://frontend.skillstorm-congo.com/", result.getUrl());
    //     verify(httpServletResponse).addCookie(any(Cookie.class));
    // }

    // @Test
    // public void testOauth2LoginInvalid() {}

    //     authService.oauth2Login(null, httpServletResponse);
    // }

    @Test
    public void testUpdatePassword() {
        UserCredentials user = new UserCredentials();
        user.setPassword(password);

        when(userCredentialsRepo.findByUsername(anyString()))
        .thenReturn(Optional.ofNullable(user));

        when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(user);

        String response = authService.updatePassword(username, password);

        assertEquals("Password updated!", response);
    }

    @Test
    public void testUpdatePasswordInvalid() {
        when(userCredentialsRepo.findByUsername(anyString()))
        .thenReturn(Optional.empty());

        String response = authService.updatePassword(username, password);

        assertEquals("User not found", response);
    }

    // @Test
    // public void testFindOrCreateUser() {
    //     when(userCredentialsRepo.findByUsername(anyString()))
    //     .thenReturn(Optional.empty());

    //         UserCredentials newUser = UserCredentials.builder()
    //         .id(1)
    //         .username(username)
    //         .oauth2Idp(String.valueOf(Oauth2AuthorizationServer.GOOGLE))
    //         .userRole(String.valueOf(UserRole.USER))
    //         .build();

    //     when(userCredentialsRepo.save(any(UserCredentials.class))).thenReturn(newUser);

    //     AuthService authServiceSpy = spy(authService);
    //     doNothing().when(authServiceSpy).createUserInUserService(anyInt(), anyString());
    //     authService.findOrCreateUser(username);

    //     assertEquals(1, newUser.getId());
    //     assertEquals(username, newUser.getUsername());
    // }

    @Test
    public void testFindOrCreateUserInvalid() {
        when(userCredentialsRepo.findByUsername(anyString())).thenReturn(Optional.ofNullable(new UserCredentials()));

        authService.findOrCreateUser(username);
    }

    @Test
    public void testGetJwtClaim() {
        String token = "token";

        when(tokenService.decodeJwt(anyString())).thenReturn(token);

        String newToken = authService.getJwtClaim(token);

        assertEquals(token, newToken);
    }

    @Test
    public void testCheckForUserServiceInstance() {
        when(loadBalancerClient.choose(anyString())).thenReturn(mock(ServiceInstance.class));

        boolean response = authService.checkForUserServiceInstance();

        assertTrue(response);
    }

    @Test
    public void testCheckForUserServiceInstanceInvalid() {
        when(loadBalancerClient.choose(anyString())).thenReturn(null);

        boolean response = authService.checkForUserServiceInstance();

        assertFalse(response);
    }

    // @Test
    // public void testCreateUserInUserService() throws Exception {
    //     Integer id = 1;
    //     String uri = "http://mock-service-uri";

    //     // mock service instance for stub return
    //     ServiceInstance instance = mock(ServiceInstance.class);
    //     when(instance.getUri()).thenReturn(new URI(uri));
    //     // stub the LBC.choose to return an instance
    //     when(loadBalancerClient.choose(anyString())).thenReturn(instance);



    //     // when(restClient.post()).thenReturn(null);
    //     // Create mocks for the RestClient response flow
    //     // RestClient.RequestBodyUriSpec requestBodyUriSpecMock = mock(RestClient.RequestBodyUriSpec.class);
    //     // RestClient.RequestBodySpec requestBodySpecMock = mock(RestClient.RequestBodySpec.class);
    //     // RestClient.ResponseSpec responseSpecMock = mock(RestClient.ResponseSpec.class);

    //     // // Set up the RestClient method chaining
    //     // when(restClient.post().uri(uri).contentType(MediaType.APPLICATION_JSON).body(any(UserDto.class)).retrieve().body(ParameterizedTypeReference.class)).thenReturn(null);
    //     // when(restClient.post()).thenReturn(requestBodyUriSpecMock);
    //     // when(requestBodyUriSpecMock.uri(any(String.class))).thenReturn(requestBodySpecMock); 
    //     // when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
    //     // when(requestBodySpecMock.body(any(UserDto.class))).thenReturn(requestBodySpecMock);
    //     // when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
    //     // when(responseSpecMock.body(ParameterizedTypeReference.class)).thenReturn(null);

    //     authService.createUserInUserService(id, password);
    // }

    @Test
    public void testCreateUserInUserServiceInvalid() {
        when(loadBalancerClient.choose(anyString())).thenReturn(null);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            authService.createUserInUserService(1, "test@email.com");
        });

        assertEquals("No user-service instance available", exception.getMessage());
    }

}
