package com.skillstorm.authservice.controllers;

import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.exceptions.UserNotFoundException;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.services.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/auth")
@CrossOrigin // TODO: Determine CORS origins
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
    public UserLoginDto loginUser(@RequestBody UserCredentialsDto body) throws UserNotFoundException, AuthException {
        return authService.login(body.getUsername(), body.getPassword());
    }

    @GetMapping("/login/oauth2")
    public RedirectView oauth2SocialLogin(Authentication auth, HttpServletResponse response) {
        return authService.oauth2Login(auth, response);
    }

}
