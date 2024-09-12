package com.skillstorm.authservice.exceptions;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@ExtendWith(MockitoExtension.class)
public class ExceptionHandlerAdviceTests {

    private final ExceptionHandlerAdvice exceptionHandlerAdvice = new ExceptionHandlerAdvice();

    @Test
    void testHandleEntityAlreadyExists() {
        String errorMessage = "User already exists";
        UserExistsException exception = new UserExistsException(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleEntityAlreadyExists(exception);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }

    @Test
    void testHandleEntityNotFound() {
        String errorMessage = "User not found";
        UserNotFoundException exception = new UserNotFoundException(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleEntityNotFound(exception);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }

    @Test
    void testHandleAuthenticationFailed() {
        String errorMessage = "Authentication failed";
        AuthException exception = new AuthException(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleAuthenticationFailed(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }

    @Test
    void testHandleOauth2Exception() {
        String errorMessage = "OAuth2 authentication failed";
        Oauth2Exception exception = new Oauth2Exception(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleOauth2Exception(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }
}
