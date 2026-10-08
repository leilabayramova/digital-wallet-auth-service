package com.example.digitalwalletauthservice.repository;

import com.example.digitalwalletauthservice.entity.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CredentialRepository extends JpaRepository<CredentialEntity, Long> {

    boolean existsByEmail(String email);

    Optional<CredentialEntity> findByEmail(String email);

    Optional<CredentialEntity> findByUserId(Long userId);
}
