package com.skillstorm.authservice.services;

import com.skillstorm.authservice.exceptions.AppUserAlreadyExistsException;
import com.skillstorm.authservice.exceptions.AppUserAuthException;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthRepository authRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authManager;

    private final TokenService tokenService;

    @Autowired
    public AuthService(AuthRepository authRepository, PasswordEncoder passwordEncoder, AuthenticationManager authManager, TokenService tokenService) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
        this.authManager = authManager;
        this.tokenService = tokenService;
    }

    public UserCredentialsDto registerUser(String username, String password) throws AppUserAlreadyExistsException {
        if (authRepository.existsByUsername(username)) {
            throw new AppUserAlreadyExistsException("That username is not available.");
        }

        String encodedPassword = passwordEncoder.encode(password);
        UserCredentials newUser = UserCredentials.builder()
                .username(username)
                .password(encodedPassword)
                .userRole("USER")
                .build();
        authRepository.save(newUser);

        return UserCredentialsDto.builder()
                .username(newUser.getUsername())
                .password("Hashed and saved in db")
                .build();
    }

    /*
     *  - Find & authenticate a username & password using the AuthenticationManager.
     *  - Generate a token to send to TokenService.
     *  - TokenService generates the JWT.
     *  - Send JWT to frontend so it can store it and be logged in.
     */
    public UserLoginDto loginUser(String username, String password) throws AppUserAuthException {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            String token = tokenService.generateJwt(auth);

            return UserLoginDto.builder()
                    .jwt(token)
                    .build();
        } catch (AuthenticationException e) {
            throw new AppUserAuthException("User not found or bad credentials.");
        }
    }

}
