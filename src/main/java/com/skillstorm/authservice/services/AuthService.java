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
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
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

@Service
public class AuthService {

    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final TokenService tokenService;
    private final LoadBalancerClient loadBalancerClient;
    private final RestClient restClient;
    
    public AuthService(
            UserCredentialsRepository userCredentialsRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authManager,
            TokenService tokenService,
            LoadBalancerClient loadBalancerClient) {
        this.userCredentialsRepository = userCredentialsRepository;
        this.passwordEncoder = passwordEncoder;
        this.authManager = authManager;
        this.tokenService = tokenService;
        this.loadBalancerClient = loadBalancerClient;
        this.restClient = RestClient.builder()
                .build();
    }

    public UserCredentialsDto register(String username, String password) throws UserExistsException {
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

            userCredentialsRepository.save(newUser);
            UserDto userDto = createUserInUserService(username);

            // In case the IDs ever diverge, return the ID from the User db to the frontend
            // Other services communicate with the User service, so its ID should be the source of truth
            Integer userServiceId = userDto.getId();

            return UserCredentialsDto.builder()
                    .id(userServiceId)
                    .username(newUser.getUsername())
                    .password("Hashed and saved in db")
                    .build();
        } catch (UserExistsException e) {
            throw new UserExistsException("That username is not available.");
        } catch (Exception e) {
            throw new RuntimeException("Error: " + e.getMessage());
        }
    }

    /*
     *  - Find & authenticate a username & password using the AuthenticationManager
     *  - Generate a token to send to TokenService
     *  - TokenService generates the JWT
     *  - Send JWT to frontend so it can store it and be logged in
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
            // Redirect URL is still TBD
            RedirectView redirectView = new RedirectView("/");
            redirectView.setContextRelative(true);

            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) auth;

            // If the user doesn't exist, register by saving the name and authorization provider in the db
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

    public Long findIdByUsername(String email) {
        return userCredentialsRepository.findIdByUsername(email);
    }

    public void findOrCreateUser(String email) {
        // Users who register using OAuth2 don't have a password to store
        if (userCredentialsRepository.findByUsername(email).isEmpty()) {
            UserCredentials user = new UserCredentials();
            user.setUsername(email);
            user.setOauth2Idp(String.valueOf(Oauth2AuthorizationServer.GOOGLE));
            user.setUserRole(String.valueOf(UserRole.USER));
            userCredentialsRepository.save(user);

            // TODO: Send request to User service to create a new User
            // In case the IDs ever diverge, be sure to return the ID from the User db to the frontend
            // Other services communicate with the User service, so its ID should be the source of truth
        }
    }

    // HTTP (RestClient) communication with the User service
    public UserDto createUserInUserService(String email) {
        try {
            ServiceInstance instance = loadBalancerClient.choose("user-service");
            UserDto userDto = UserDto.builder()
                    .email(email)
                    .build();

            if (instance != null) {
                String serviceUrl = instance.getUri().toString();

                return restClient.post()
                        .uri(serviceUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(userDto)
                        .retrieve()
                        .body(new ParameterizedTypeReference<>() {});
            } else {
                throw new IllegalStateException("No instances available for user-service");
            }
        } catch (HttpClientErrorException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

}
