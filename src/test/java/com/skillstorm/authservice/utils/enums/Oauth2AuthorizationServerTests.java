package com.skillstorm.authservice.utils.enums;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class Oauth2AuthorizationServerTests {
    // Make sure that the value isn't null
    @Test
    public void testAuthServerExists() {
        assertNotNull(Oauth2AuthorizationServer.GOOGLE);
    }
}
