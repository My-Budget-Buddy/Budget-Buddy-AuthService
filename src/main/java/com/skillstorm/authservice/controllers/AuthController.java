package com.skillstorm.authservice.controllers;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.UserNotFoundException;
import com.skillstorm.authservice.models.JwtValidationDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.services.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.QueryParam;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public UserCredentialsDto registerUser(@RequestBody UserCredentialsDto body) throws UserExistsException {
        return authService.register(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public UserLoginDto loginUser(@RequestBody UserCredentialsDto body, HttpServletResponse response) throws UserNotFoundException, AuthException {
        return authService.login(body.getUsername(), body.getPassword(), response);
    }

    @GetMapping("/login/oauth2")
    public RedirectView oauth2SocialLogin(Authentication auth, HttpServletResponse response) {
        return authService.oauth2Login(auth, response);
    }

    // Endpoint to validate a JWT if any services require it.
    @GetMapping("/validate")
    public ResponseEntity<JwtValidationDto> validateJwt(@RequestHeader(name = "Authorization") String header, Authentication auth) {
        String token = header.substring(7);
        String userId = authService.getJwtClaim(token);

        JwtValidationDto dto = new JwtValidationDto();
        dto.setJwtSubject(auth.getName());
        dto.setJwtClaim("userId: " + userId);

        // Spring Security decodes the JWT; if it's invalid, return a 401 UNAUTHORIZED.
        return new ResponseEntity<>(dto, HttpStatus.OK);
    }

}
