package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.InvalidOperationException;
import com.example.digitalwalletauthservice.exception.UserNotFoundException;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    private static final JwtUserPrincipal ADMIN = new JwtUserPrincipal(1L, "admin@example.com", Role.ADMIN);

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private TokenService tokenService;

    private AdminService adminService;

    @BeforeEach
    void setUp() {
        adminService = new AdminService(credentialRepository, tokenService);
    }

    private CredentialEntity target() {
        return CredentialEntity.builder()
                .id(2L).userId(5L).email("leila@example.com").passwordHash("hash").role(Role.USER).build();
    }

    @Test
    void updateRole_shouldChangeRoleAndRevokeSessions() {
        CredentialEntity target = target();
        when(credentialRepository.findByUserId(5L)).thenReturn(Optional.of(target));

        UserInfoResponseDto result = adminService.updateRole(ADMIN, 5L, Role.ADMIN);

        assertThat(target.getRole()).isEqualTo(Role.ADMIN);
        assertThat(result.getRole()).isEqualTo(Role.ADMIN);
        verify(credentialRepository).save(target);
        verify(tokenService).revokeAll(5L);
    }

    @Test
    void updateRole_shouldRejectChangingOwnRole() {
        assertThatThrownBy(() -> adminService.updateRole(ADMIN, 1L, Role.USER))
                .isInstanceOf(InvalidOperationException.class);

        verify(credentialRepository, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void updateRole_shouldThrow_whenTargetDoesNotExist() {
        when(credentialRepository.findByUserId(5L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> adminService.updateRole(ADMIN, 5L, Role.ADMIN))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void setEnabled_shouldDisableAndRevokeSessions() {
        CredentialEntity target = target();
        when(credentialRepository.findByUserId(5L)).thenReturn(Optional.of(target));

        adminService.setEnabled(ADMIN, 5L, false);

        assertThat(target.isEnabled()).isFalse();
        verify(tokenService).revokeAll(5L);
    }

    @Test
    void setEnabled_shouldNotRevokeSessions_whenEnabling() {
        CredentialEntity target = target();
        target.setEnabled(false);
        when(credentialRepository.findByUserId(5L)).thenReturn(Optional.of(target));

        adminService.setEnabled(ADMIN, 5L, true);

        assertThat(target.isEnabled()).isTrue();
        verify(tokenService, never()).revokeAll(5L);
    }

    @Test
    void setEnabled_shouldRejectDisablingSelf() {
        assertThatThrownBy(() -> adminService.setEnabled(ADMIN, 1L, false))
                .isInstanceOf(InvalidOperationException.class);
    }

    @Test
    void unlock_shouldClearFailuresAndLock() {
        CredentialEntity target = target();
        target.setFailedLoginAttempts(4);
        target.setLockedUntil(LocalDateTime.now().plusMinutes(10));
        when(credentialRepository.findByUserId(5L)).thenReturn(Optional.of(target));

        adminService.unlock(ADMIN, 5L);

        assertThat(target.getFailedLoginAttempts()).isZero();
        assertThat(target.getLockedUntil()).isNull();
        verify(credentialRepository).save(target);
    }
}
