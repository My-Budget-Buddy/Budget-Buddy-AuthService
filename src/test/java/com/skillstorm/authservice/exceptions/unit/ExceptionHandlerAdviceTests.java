package com.skillstorm.authservice.exceptions.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.ExceptionHandlerAdvice;
import com.skillstorm.authservice.exceptions.Oauth2Exception;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.exceptions.UserNotFoundException;

@ExtendWith(MockitoExtension.class)
public class ExceptionHandlerAdviceTests {

    private final ExceptionHandlerAdvice exceptionHandlerAdvice = new ExceptionHandlerAdvice();

    @Test
    void testHandleEntityAlreadyExists() {
        // Check that the response is correct for an EntityAlreadyExistsException
        String errorMessage = "User already exists";
        UserExistsException exception = new UserExistsException(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleEntityAlreadyExists(exception);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }

    @Test
    void testHandleEntityNotFound() {
        // Check that the response is correct for an EntityNotFoundException
        String errorMessage = "User not found";
        UserNotFoundException exception = new UserNotFoundException(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleEntityNotFound(exception);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }

    @Test
    void testHandleAuthenticationFailed() {
        // Check that the response is correct for an AuthException
        String errorMessage = "Authentication failed";
        AuthException exception = new AuthException(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleAuthenticationFailed(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }

    @Test
    void testHandleOauth2Exception() {
        // Check that the response is correct for an Oauth2Exception
        String errorMessage = "OAuth2 authentication failed";
        Oauth2Exception exception = new Oauth2Exception(errorMessage);

        ResponseEntity<String> response = exceptionHandlerAdvice.handleOauth2Exception(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(errorMessage, response.getBody());
    }
}
