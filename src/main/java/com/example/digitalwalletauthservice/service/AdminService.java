package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.InvalidOperationException;
import com.example.digitalwalletauthservice.exception.UserNotFoundException;
import com.example.digitalwalletauthservice.mapper.AuthMapper;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final CredentialRepository credentialRepository;
    private final TokenService tokenService;

    /**
     * Sessions are revoked so that the user's next access token carries the new role. Access tokens that
     * were already issued stay valid until they expire (short-lived by design).
     */
    @Transactional
    public UserInfoResponseDto updateRole(JwtUserPrincipal actor, Long targetUserId, Role role) {
        rejectSelfModification(actor, targetUserId);

        CredentialEntity credential = findCredential(targetUserId);
        credential.setRole(role);
        credentialRepository.save(credential);

        tokenService.revokeAll(targetUserId);

        AuditLog.event("ADMIN_ROLE_CHANGED", targetUserId, "by=" + actor.userId() + " role=" + role);

        return AuthMapper.toUserInfoResponseDto(credential);
    }

    @Transactional
    public UserInfoResponseDto setEnabled(JwtUserPrincipal actor, Long targetUserId, boolean enabled) {
        rejectSelfModification(actor, targetUserId);

        CredentialEntity credential = findCredential(targetUserId);
        credential.setEnabled(enabled);
        credentialRepository.save(credential);

        if (!enabled) {
            tokenService.revokeAll(targetUserId);
        }

        AuditLog.event(enabled ? "ADMIN_USER_ENABLED" : "ADMIN_USER_DISABLED", targetUserId, "by=" + actor.userId());

        return AuthMapper.toUserInfoResponseDto(credential);
    }

    @Transactional
    public void unlock(JwtUserPrincipal actor, Long targetUserId) {
        CredentialEntity credential = findCredential(targetUserId);
        credential.clearLoginFailures();
        credentialRepository.save(credential);

        AuditLog.event("ADMIN_USER_UNLOCKED", targetUserId, "by=" + actor.userId());
    }

    private CredentialEntity findCredential(Long userId) {
        return credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    private void rejectSelfModification(JwtUserPrincipal actor, Long targetUserId) {
        if (actor.userId().equals(targetUserId)) {
            throw new InvalidOperationException("Administrators cannot change their own role or status");
        }
    }
}
