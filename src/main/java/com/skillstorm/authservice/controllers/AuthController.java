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
    public ResponseEntity<Object> registerUser(@RequestBody UserCredentialsDto body) throws UserExistsException {
        authService.register(body.getUsername(), body.getPassword());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<UserLoginDto> loginUser(@RequestBody UserCredentialsDto body, HttpServletResponse response) throws UserNotFoundException, AuthException {
        return new ResponseEntity<>(authService.login(body.getUsername(), body.getPassword(), response), HttpStatus.OK);
    }

    @GetMapping("/login/oauth2")
    public RedirectView oauth2SocialLogin(Authentication auth, HttpServletResponse response) {
        return authService.oauth2Login(auth, response);
    }

    @GetMapping("/logout/redirect")
    public RedirectView logout() {
        return new RedirectView("https://frontend.skillstorm-congo.com/");
    }

    // Endpoint to validate a JWT and return the user ID embedded in it for the Gateway.
    @GetMapping("/validate")
    public ResponseEntity<JwtValidationDto> validateJwt(@RequestHeader(name = "Authorization") String header, Authentication auth) {
        String token = header.substring(7);
        String userId = authService.getJwtClaim(token);

        JwtValidationDto dto = new JwtValidationDto();
        dto.setJwtSubject(auth.getName());
        dto.setJwtClaim(userId);

        // Spring Security decodes the JWT; if it's invalid, return a 401 UNAUTHORIZED.
        return new ResponseEntity<>(dto, HttpStatus.OK);
    }

}
