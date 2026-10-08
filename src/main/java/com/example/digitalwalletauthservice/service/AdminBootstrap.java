package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.client.UserProfileGateway;
import com.example.digitalwalletauthservice.config.AuthProperties;
import com.example.digitalwalletauthservice.dto.CreateUserRequestDto;
import com.example.digitalwalletauthservice.dto.UserProfileResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Creates the first administrator when auth.bootstrap-admin.email and .password are configured
 * (use environment variables for the password). Does nothing if that account already exists.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminBootstrap implements ApplicationRunner {

    private final AuthProperties authProperties;
    private final CredentialRepository credentialRepository;
    private final UserProfileGateway userProfileGateway;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        AuthProperties.BootstrapAdmin admin = authProperties.getBootstrapAdmin();

        if (!admin.isConfigured()) {
            return;
        }

        String email = admin.getEmail().trim().toLowerCase(Locale.ROOT);

        if (credentialRepository.existsByEmail(email)) {
            log.info("Bootstrap admin already exists, skipping");
            return;
        }

        try {
            UserProfileResponseDto profile = userProfileGateway.createUser(
                    new CreateUserRequestDto(admin.getFullName(), email),
                    UserProfileGateway.idempotencyKeyFor(email)
            );

            CredentialEntity credential = credentialRepository.save(CredentialEntity.builder()
                    .userId(profile.getId())
                    .email(email)
                    .passwordHash(passwordEncoder.encode(admin.getPassword()))
                    .role(Role.ADMIN)
                    .emailVerified(true)
                    .build());

            AuditLog.event("BOOTSTRAP_ADMIN_CREATED", credential.getUserId());
        } catch (RuntimeException exception) {
            log.error("Could not create bootstrap admin: {}", exception.getMessage());
        }
    }
}
