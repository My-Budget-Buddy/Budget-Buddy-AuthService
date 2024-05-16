package com.skillstorm.authservice.controllers;

import com.skillstorm.authservice.exceptions.AppUserAlreadyExistsException;
import com.skillstorm.authservice.exceptions.AppUserAuthException;
import com.skillstorm.authservice.exceptions.AppUserNotFoundException;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin // TODO: Determine CORS origins
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public UserCredentialsDto registerUser(@RequestBody UserCredentialsDto body) throws AppUserAlreadyExistsException {
        return authService.registerUser(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public UserLoginDto loginUser(@RequestBody UserCredentialsDto body) throws AppUserNotFoundException, AppUserAuthException {
        return authService.loginUser(body.getUsername(), body.getPassword());
    }

}
