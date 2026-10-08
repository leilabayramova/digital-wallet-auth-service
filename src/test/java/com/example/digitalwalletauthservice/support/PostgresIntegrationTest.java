package com.example.digitalwalletauthservice.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.junit.jupiter.api.Tag;
import org.testcontainers.junit.jupiter.Container;

/**
 * Base class for tests that need a real PostgreSQL (Liquibase migrations included).
 * Requires a running Docker daemon; nothing else has to be set up by hand.
 */
@SpringBootTest(properties = {
        "jwt.secret=integration-test-secret-key-at-least-32-bytes",
        "auth.max-failed-login-attempts=3",
        "auth.require-email-verification=false"
})
@ActiveProfiles("test")
@Testcontainers
@Tag("integration")
public abstract class PostgresIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");
}
