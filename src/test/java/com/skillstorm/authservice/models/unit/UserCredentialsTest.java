package com.skillstorm.authservice.models.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.skillstorm.authservice.models.UserCredentials;

public class UserCredentialsTest {

    private UserCredentials userCredentials;
    private Integer id;
    private String username;
    private String password;
    private String oauth2Idp;
    private String userRole;

    @BeforeEach
    public void setup() {
        id = 1;
        username = "user";
        password = "secret";
        oauth2Idp = "oAuthIdp";
        userRole = "role";
        userCredentials = UserCredentials.builder()
            .id(id)
            .username(username)
            .password(password)
            .oauth2Idp(oauth2Idp)
            .userRole(userRole)
            .build();
    }

    // test constructor with no args
    @Test
    public void testEmptyConstructor() {
        userCredentials = new UserCredentials();
        assertNotNull(userCredentials);
    }

    // test constructor with all args
    @Test
    public void testLoadedConstructor() {
        assertEquals(id, userCredentials.getId());
        assertEquals(username, userCredentials.getUsername());
        assertEquals(password, userCredentials.getPassword());
        assertEquals(oauth2Idp, userCredentials.getOauth2Idp());
        assertEquals(userRole, userCredentials.getUserRole());
    }

    // test toString method
    @Test
    public void testToString() {
        String expectedString = "UserCredentials(id=" + id + ", username=" + username + ", password=" + password + ", oauth2Idp=" + oauth2Idp + ", userRole=" + userRole + ")";
        assertEquals(expectedString, userCredentials.toString());
    }

    @Test
    public void testGetAuthorities() {
        Collection<? extends GrantedAuthority> authorities = userCredentials.getAuthorities();
        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority(userRole)));
    }

    // isAccountNonExpired should always return true
    @Test
    public void testIsAccountNonExpired() {
        assertTrue(userCredentials.isAccountNonExpired());
    }

    // isAccountNonLock should always return true
    @Test
    public void testIsAccountNonLocked() {
        assertTrue(userCredentials.isAccountNonLocked());
    }

    // isCredentialNonExpired should always return true
    @Test
    public void testIsCrendentialsNonExpired() {
        assertTrue(userCredentials.isCredentialsNonExpired());
    }

    // isEnabled should always return true
    @Test
    public void testIsEnabled() {
        assertTrue(userCredentials.isEnabled());
    }
}
