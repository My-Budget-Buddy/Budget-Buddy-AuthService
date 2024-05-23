package com.skillstorm.authservice.services;

import com.skillstorm.authservice.exceptions.UserExistsException;
import com.skillstorm.authservice.exceptions.AuthException;
import com.skillstorm.authservice.models.UserCredentials;
import com.skillstorm.authservice.models.UserCredentialsDto;
import com.skillstorm.authservice.models.UserDto;
import com.skillstorm.authservice.models.UserLoginDto;
import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.utils.enums.Oauth2AuthorizationServer;
import com.skillstorm.authservice.utils.enums.UserRole;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Service
public class AuthService {

    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final TokenService tokenService;
    private final LoadBalancerClient loadBalancerClient;
    private final DiscoveryClient discoveryClient;
    private final RestClient restClient;
    
    public AuthService(
            UserCredentialsRepository userCredentialsRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authManager,
            TokenService tokenService,
            LoadBalancerClient loadBalancerClient,
            DiscoveryClient discoveryClient) {
        this.userCredentialsRepository = userCredentialsRepository;
        this.passwordEncoder = passwordEncoder;
        this.authManager = authManager;
        this.tokenService = tokenService;
        this.loadBalancerClient = loadBalancerClient;
        this.discoveryClient = discoveryClient;
        this.restClient = RestClient.builder()
                .build();
    }

    public void register(String username, String password) throws UserExistsException {
        try {
            if (userCredentialsRepository.existsByUsername(username)) {
                throw new UserExistsException("That username is not available.");
            }

            String encodedPassword = passwordEncoder.encode(password);
            UserCredentials newUser = UserCredentials.builder()
                    .username(username)
                    .password(encodedPassword)
                    .userRole("USER")
                    .build();

            UserCredentials savedUser = userCredentialsRepository.save(newUser);
            createUserInUserService(savedUser.getId(), username);

        } catch (UserExistsException e) {
            throw new UserExistsException("That username is not available.");
        } catch (Exception e) {
            throw new RuntimeException("Error: " + e.getMessage());
        }
    }

    /*
     *  - Find & authenticate a username/password using the AuthenticationManager implementation
     *  - Generate a token to send to TokenService
     *  - TokenService generates the JWT
     *  - Send JWT to frontend so it can store it and be logged in
     */
    public void login(String username, String password, HttpServletResponse response) throws AuthException {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            String token = tokenService.generateJwt(auth);

            Cookie cookie = new Cookie("jwt", token);
            cookie.setHttpOnly(false);
            cookie.setPath("/");
            response.addCookie(cookie);
        } catch (AuthenticationException e) {
            throw new AuthException("User not found or bad credentials.");
        }
    }

    public RedirectView oauth2Login(Authentication auth, HttpServletResponse response) {
        try {
            // Redirect URL is still TBD
            RedirectView redirectView = new RedirectView("/");
            redirectView.setContextRelative(true);

            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) auth;

            // If the user doesn't exist, register by saving the name and authorization provider in the db
            String email = oauthToken.getPrincipal().getAttribute("email");
            findOrCreateUser(email);

            String token = tokenService.generateJwt(auth);
            Cookie cookie = new Cookie("jwt", token);
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
        // Users who register using OAuth2 don't have a password to store
        if (userCredentialsRepository.findByUsername(email).isEmpty()) {
            UserCredentials newUser = new UserCredentials();
            newUser.setUsername(email);
            newUser.setOauth2Idp(String.valueOf(Oauth2AuthorizationServer.GOOGLE));
            newUser.setUserRole(String.valueOf(UserRole.USER));

            UserCredentials savedUser = userCredentialsRepository.save(newUser);
            createUserInUserService(savedUser.getId(), newUser.getUsername());
        }
    }

    public String getJwtClaim(String token) {
        return tokenService.decodeJwt(token);
    }

    // HTTP (RestClient) communication with the User service
    public void createUserInUserService(Integer id, String email) {
        try {
            ServiceInstance instance = loadBalancerClient.choose("user-service");
            UserDto userDto = UserDto.builder()
                    .id(id)
                    .email(email)
                    .build();

            if (instance != null) {
                String serviceUrl = instance.getUri().toString().concat("/users");

                restClient.post()
                        .uri(serviceUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(userDto)
                        .retrieve()
                        .body(new ParameterizedTypeReference<>() {});
            } else {
                throw new IllegalStateException("No user-service instance available");
            }
        } catch (HttpClientErrorException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

}
