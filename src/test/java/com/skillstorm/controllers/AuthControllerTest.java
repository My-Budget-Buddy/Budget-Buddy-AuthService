package com.skillstorm.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.view.RedirectView;

import com.skillstorm.authservice.controllers.AuthController;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.models.JwtValidationDto;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.AuthService;

import jakarta.servlet.http.HttpServletResponse;

public class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private UserCredentialsRepository userCredentialsRepo;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private UserCredentialsDto body;

    @InjectMocks
    private AuthController authController;
    private AutoCloseable closeable;

    @BeforeEach
    public void setup() {
        closeable = MockitoAnnotations.openMocks(this);
        body = new UserCredentialsDto("user", "secret");
    }

    @AfterEach
    public void teardown() throws Exception {
        closeable.close();
    }

    @Test
    public void testRegisterUser() throws Exception {
        ResponseEntity<Object> response = authController.registerUser(body);

        // make sure register is called once using these params
        verify(authService).register(body.getUsername(), body.getPassword());
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    @Test
    public void testRegisterUserInvalid() throws Exception {

        // stub existsbyusername to return true for condition to trigger exception
        when(userCredentialsRepo.existsByUsername(body.getUsername()))
        .thenReturn(true);

        // stub exception throw when authservice is called with previous stub
        doThrow(new UserExistsException("That username is not available."))
        .when(authService).register(body.getUsername(), body.getPassword());

        // store the exception thrown and verify correct exception was thrown
        UserExistsException exception = assertThrows(UserExistsException.class, () -> {
            authController.registerUser(body);
        });

        // verify the exception message matches with stub
        assertEquals("That username is not available.", exception.getMessage());
    }

    /**
     *     loginUser takes in USerCredentials body and HttpServletResponse response
     *      calls authservice.login(with body username, password, and reponse)
     *      returns responseentity with authrservice login return and httpstatus
     *      methods called: userCredentialsRepo.findbyusername(username)
     *      found user orelse throw
     *     authservice.login returns userlogindto
     * */ 

    // successful test of login user
    @Test
    public void testLoginUser() throws Exception {
        // Optional<UserCredentials> foundUser = Optional.ofNullable(new UserCredentials());
        UserLoginDto userLoginDto = new UserLoginDto();
        userLoginDto.setUsername(body.getUsername());

        // stub findbyusername to return optional usercredentials
        // when(userCredentialsRepo.findByUsername(body.getUsername()))
        // .thenReturn(foundUser);

        // stub login to return predefined userlogindto
        when(authService.login(body.getUsername(), body.getPassword(), httpServletResponse))
        .thenReturn(userLoginDto);

        ResponseEntity<UserLoginDto> response = authController.loginUser(body, httpServletResponse);

        // verify status code returns OK
        assertEquals(HttpStatus.OK, response.getStatusCode());
        // verify response body username matches what was stubbed
        assertEquals(body.getUsername(), response.getBody().getUsername());
    }

    @Test
    public void testLoginUserInvalid() throws Exception {
        String expectedMessage = "User not found or bad credentials.";

        // stub findbyusername when it cannot find a matching username in db
        // when(userCredentialsRepo.findByUsername(body.getUsername()))
        // .thenReturn(null);

        // stub exception thrown since username cannot be found
        when(authService.login(body.getUsername(), body.getPassword(), httpServletResponse))
        .thenThrow(new AuthException(expectedMessage));

        // store the exception thrown from loginuser
        AuthException exception = assertThrows(AuthException.class, () -> {
            authController.loginUser(body, httpServletResponse);
        });

        // verify it messages match
        assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    public void testOAuth2SocialLogin() {
        Authentication auth = new UsernamePasswordAuthenticationToken(body.getUsername(), body.getPassword());
        RedirectView redirectView = new RedirectView("http://test-example.com/");

        // stub oauth2login to return a predefined redirect obj
        when(authService.oauth2Login(any(Authentication.class), any(HttpServletResponse.class))).thenReturn(redirectView);

        // store the redirect from controller method
        RedirectView actualRedirectView = authController.oauth2SocialLogin(auth, httpServletResponse);

        // verify urls match 
        assertEquals(redirectView.getUrl(), actualRedirectView.getUrl());
    }

    @Test
    public void testLogout() {
        RedirectView redirectView = authController.logout();

        // verify urls match from logout method
        assertEquals("https://frontend.skillstorm-congo.com/", redirectView.getUrl());
    }

    @Test
    public void testUpdatePassword() throws Exception {
        // stub updatepassword to return message for successful password update
        when(authService.updatePassword(body.getUsername(), body.getPassword()))
        .thenReturn("Password Updated!");

        // store the response as string RE obj
        ResponseEntity<String> response = authController.updatePassword(body);

        // verify success message is returned
        assertEquals("Password Updated!", response.getBody());
        // verifiy response code matches
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void testUpdatePasswordInvalid() throws Exception {
        // stub updatepassword to return message for unsuccessful password update 
        when(authService.updatePassword(body.getUsername(), body.getPassword()))
        .thenReturn("User not found");
        // .thenThrow(new UserNotFoundException("User not found"));
    
        // store exception thrown from controller
        // UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
        //     authController.updatePassword(body);
        // });
        ResponseEntity<String> exception = authController.updatePassword(body);
    
        // verify exception messages match
        assertEquals("User not found", exception.getBody());
    }

    @Test
    public void testValidateJwt() {
        String header = "authtoken";
        String userId = "userId";
        Authentication auth = new UsernamePasswordAuthenticationToken(body.getUsername(), body.getPassword());

        // stub getjwtclaim to return predefined userid
        when(authService.getJwtClaim(header)).thenReturn(userId);

        ResponseEntity<JwtValidationDto> jDto = authController.validateJwt(header, auth);

        // verify
        assertEquals(body.getUsername(), jDto.getBody().getJwtSubject());
        assertEquals(HttpStatus.OK, jDto.getStatusCode());
    }
}
