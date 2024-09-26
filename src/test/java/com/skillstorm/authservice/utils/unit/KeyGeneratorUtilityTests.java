package com.skillstorm.authservice.utils.unit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.skillstorm.authservice.utils.KeyGeneratorUtility;

@ExtendWith(MockitoExtension.class)
public class KeyGeneratorUtilityTests {

    @Test
    void testGenerateRsaKey() {
    KeyPair mockKeyPair = new KeyPair(Mockito.mock(java.security.PublicKey.class), Mockito.mock(java.security.PrivateKey.class));

    try (MockedStatic<KeyGeneratorUtility> mockedStatic = Mockito.mockStatic(KeyGeneratorUtility.class)) {
        mockedStatic.when(KeyGeneratorUtility::generateRsaKey).thenReturn(mockKeyPair);

        KeyPair keyPair = KeyGeneratorUtility.generateRsaKey();

        // Check that all keys are not null
        assertNotNull(keyPair, "KeyPair should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
    }
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
