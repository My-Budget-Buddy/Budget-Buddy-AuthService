package com.skillstorm.authservice.utils;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ExtendWith(MockitoExtension.class)
public class RsaKeyPropertiesTests {

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private RsaKeyProperties rsaKeyProperties;

    @BeforeEach
    void setUp() {
        // Mock the key pair
        publicKey = mock(RSAPublicKey.class);
        privateKey = mock(RSAPrivateKey.class);

        // Mock KeyGeneratorUtility.generateRsaKey() to return the mock key pair
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        try (MockedStatic<KeyGeneratorUtility> mockedStatic = Mockito.mockStatic(KeyGeneratorUtility.class)) {
            mockedStatic.when(KeyGeneratorUtility::generateRsaKey).thenReturn(keyPair);

            rsaKeyProperties = new RsaKeyProperties(); // Initialize RSA key properties
        }
    }

    @Test
    void testGetPublicKey() {
        // Test that the public key is the same as the mock public key
        assertEquals(publicKey, rsaKeyProperties.getPublicKey());
    }

    @Test
    void testGetPrivateKey() {
        // Test that the private key is the same as the mock private key
        assertEquals(privateKey, rsaKeyProperties.getPrivateKey());
    }

    @Test
    void testSetPublicKey() {
        // Test that the public key can be set to a new public key
        RSAPublicKey newPublicKey = mock(RSAPublicKey.class);
        rsaKeyProperties.setPublicKey(newPublicKey);
        assertEquals(newPublicKey, rsaKeyProperties.getPublicKey());
    }

    @Test
    void testSetPrivateKey() {
        // Test that the private key can be set to a new private key
        RSAPrivateKey newPrivateKey = mock(RSAPrivateKey.class);
        rsaKeyProperties.setPrivateKey(newPrivateKey);
        assertEquals(newPrivateKey, rsaKeyProperties.getPrivateKey());
    }
}