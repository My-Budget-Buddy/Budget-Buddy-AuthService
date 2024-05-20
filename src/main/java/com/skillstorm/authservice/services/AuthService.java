package com.skillstorm.authservice.services;

import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.AuthRepository;
import com.skillstorm.authservice.utils.enums.Oauth2AuthorizationServer;
import com.skillstorm.authservice.utils.enums.UserRole;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class AuthService {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final TokenService tokenService;
    
    public AuthService(
            AuthRepository authRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authManager,
            TokenService tokenService) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
        this.authManager = authManager;
        this.tokenService = tokenService;
    }

    public UserCredentialsDto register(String username, String password) throws UserExistsException {
        try {
            if (authRepository.existsByUsername(username)) {
                throw new UserExistsException("That username is not available.");
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
        } catch (UserExistsException e) {
            throw new UserExistsException("That username is not available.");
        } catch (Exception e) {
            throw new RuntimeException("Error: " + e.getMessage());
        }

        // TODO: Send request to User Service to create a new User
        // In case the IDs ever diverge, be sure to return the ID from the User db to the frontend
    }

    /*
     *  - Find & authenticate a username & password using the AuthenticationManager.
     *  - Generate a token to send to TokenService.
     *  - TokenService generates the JWT.
     *  - Send JWT to frontend so it can store it and be logged in.
     */
    public UserLoginDto login(String username, String password) throws AuthException {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            String token = tokenService.generateJwt(auth);

            return UserLoginDto.builder()
                    .jwt(token)
                    .build();
        } catch (AuthenticationException e) {
            throw new AuthException("User not found or bad credentials.");
        }
    }

    public RedirectView oauth2Login(Authentication auth, HttpServletResponse response) {
        try {
            // May be necessary to redirect to a context-enabled relative path, depending on final deployment.
            RedirectView redirectView = new RedirectView("/");
            redirectView.setContextRelative(true);

            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) auth;

            String email = oauthToken.getPrincipal().getAttribute("email");
            findOrCreateUser(email);

            String jwt = tokenService.generateJwt(auth);
            Cookie cookie = new Cookie("jwt", jwt);
            cookie.setHttpOnly(false);
            cookie.setPath("/");
            response.addCookie(cookie);

            return redirectView;
        } catch (Exception e) {
            String errorMessage = URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
            throw new RuntimeException("Error: " + errorMessage);
        }
    }

    public void findOrCreateUser(String email) {
        // Users who register using OAuth2 don't have a password to store.
        if (authRepository.findByUsername(email).isEmpty()) {
            UserCredentials user = new UserCredentials();
            user.setUsername(email);
            user.setOauth2Idp(String.valueOf(Oauth2AuthorizationServer.GOOGLE));
            user.setUserRole(String.valueOf(UserRole.USER));
            authRepository.save(user);

            // TODO: Send request to User service to create a new User
            // In case the IDs ever diverge, be sure to return the ID from the User db to the frontend
        }
    }

}
