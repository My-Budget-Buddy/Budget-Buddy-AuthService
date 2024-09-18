package com.skillstorm.authservice.services.unit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import com.skillstorm.authservice.services.TokenService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class TokenServiceTests {

    @Mock
    private JwtEncoder jwtEncoder;

    @Mock
    private JwtDecoder jwtDecoder;

    @Mock
    private UserCredentialsRepository userCredentialsRepository;

    @InjectMocks
    private TokenService tokenService;

    @Test
    void generateJwtTest() {
        String username = "testUser";
        Integer userId = 1;
        
        // Mock Authentication
        Authentication auth = Mockito.mock(Authentication.class);
        when(auth.getName()).thenReturn(username);
        
        // Mock GrantedAuthority
        GrantedAuthority authority = Mockito.mock(GrantedAuthority.class);
        when(authority.getAuthority()).thenReturn("ROLE_USER");
        
        // Explicitly stating the type so it doesn't throw a warning
        Collection<? extends GrantedAuthority> authorities = Collections.singletonList(authority);
        when(auth.getAuthorities()).thenAnswer(invocation -> authorities);
        
        // Mock repository
        when(userCredentialsRepository.findIdByUsername(username)).thenReturn(Optional.of(userId));
        
        // Mock Jwt, claims 
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .subject(username)
                .claim("userId", userId.toString())
                .expiresAt(Instant.now().plus(2, ChronoUnit.HOURS))
                .build();

        Jwt jwt = Jwt.withTokenValue("encodedToken")
                .headers(headers -> headers.put("alg", "none"))
                .claims(claimsMap -> claimsMap.putAll(claims.getClaims()))
                .build();
        
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        // Call generateJwt to get the token to test
        String token = tokenService.generateJwt(auth, username);

        // Token should have value "encodedToken"
        assertEquals("encodedToken", token);
    }

    @Test
    void decodeJwtTest() {
        // Mock JwtDecoder
        Jwt jwt = Mockito.mock(Jwt.class);
        when(jwt.getClaim("userId")).thenReturn("1");
        when(jwtDecoder.decode("token")).thenReturn(jwt);

        // Call decodeJwt method
        String userId = tokenService.decodeJwt("token");

        // Assert 1 is returned 
        assertEquals("1", userId);
    }
}