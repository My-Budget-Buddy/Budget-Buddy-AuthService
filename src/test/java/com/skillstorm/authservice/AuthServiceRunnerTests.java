package com.skillstorm.authservice;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

// By disabling spring cloud, and excluding the DataSourceAutoConfiguration and HibernateJpaAutoConfiguration,
// we can test the context loading without the DB connection
@ExtendWith(MockitoExtension.class)
@SpringBootTest(properties = { "spring.cloud.discovery.enabled=false" })
@EnableAutoConfiguration(exclude = {
    DataSourceAutoConfiguration.class,
    HibernateJpaAutoConfiguration.class
})
class AuthServiceRunnerTests {

    @MockBean
    private com.skillstorm.authservice.repositories.UserCredentialsRepository userCredentialsRepository;

    @Test
    void contextLoads() {
        // Checking Spring context loads
    }

    @Test
    void testMain() {
        // Mock the SpringApplication.run method to return null
        try (MockedStatic<SpringApplication> mockedSpringApplication = Mockito.mockStatic(SpringApplication.class)) {
            mockedSpringApplication.when(() -> SpringApplication.run(AuthServiceRunner.class, new String[]{})).thenReturn(null);

            // Call the main method w/ empty arg, which should call SpringApplication
            AuthServiceRunner.main(new String[]{});

            // Verify that SpringApplication.run was called
            mockedSpringApplication.verify(() -> SpringApplication.run(AuthServiceRunner.class, new String[]{}));
        }
    }
}
