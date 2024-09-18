package com.skillstorm.authservice.utils.enums;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class UserRoleTests {
    // Make sure that the value isn't null
    @Test
    public void testUserRoleExists() {
        assertNotNull(UserRole.USER);
    }
}
