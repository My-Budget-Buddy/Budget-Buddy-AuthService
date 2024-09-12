package com.skillstorm.authservice.utils;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class KeyGeneratorUtilityTests {

    @Test
    void testGenerateRsaKey() {
        KeyPair keyPair = KeyGeneratorUtility.generateRsaKey();

        // Check that all keys are not null
        assertNotNull(keyPair, "KeyPair should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
    }

    @Test
    void testGenerateRsaKeyNoSuchAlgorithmException() { // Throwing the NoSuchAlgorithmException
        try (MockedStatic<KeyPairGenerator> mocked = Mockito.mockStatic(KeyPairGenerator.class)) {
            mocked.when(() -> KeyPairGenerator.getInstance("RSA")).thenThrow(new NoSuchAlgorithmException());

            assertThrows(IllegalStateException.class, KeyGeneratorUtility::generateRsaKey);
        }
    }

    @Test
    void testClassInstantiation() { // Test class instantiation
        KeyGeneratorUtility utility = new KeyGeneratorUtility();
        assertNotNull(utility);
    }
}
