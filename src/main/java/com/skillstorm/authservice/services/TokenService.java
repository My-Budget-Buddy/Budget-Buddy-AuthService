package com.skillstorm.authservice.services;

import com.skillstorm.authservice.repositories.UserCredentialsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final UserCredentialsRepository userCredentialsRepository;

    public TokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserCredentialsRepository userCredentialsRepository) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userCredentialsRepository = userCredentialsRepository;
    }

    public String generateJwt(Authentication auth, String username) {
        // Take a snapshot of the time.
        Instant now = Instant.now();

        // Put all the Authorities into a string to store in the token.
        String scope = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        Optional<Integer> userIdMaybe = userCredentialsRepository.findIdByUsername(username);
        Integer userId = userIdMaybe.orElseThrow();

        // JWT claim set: The info the token holds. subject = username, claim = roles.
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .subject(auth.getName())
                .claim("userId", userId.toString())
                .expiresAt(now.plus(2, ChronoUnit.HOURS))
                .build();

        // Build the JWT token.
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String decodeJwt(String token) {
        Jwt decodedJwt = jwtDecoder.decode(token);
        return decodedJwt.getClaim("userId");
    }

}
