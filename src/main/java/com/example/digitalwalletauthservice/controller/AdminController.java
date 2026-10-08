package com.example.digitalwalletauthservice.controller;

import com.example.digitalwalletauthservice.dto.UpdateEnabledRequestDto;
import com.example.digitalwalletauthservice.dto.UpdateRoleRequestDto;
import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;
import com.example.digitalwalletauthservice.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;

    @PatchMapping("/{userId}/role")
    public UserInfoResponseDto updateRole(
            @AuthenticationPrincipal JwtUserPrincipal principal,
            @PathVariable Long userId,
            @Valid @RequestBody UpdateRoleRequestDto requestDto
    ) {
        return adminService.updateRole(principal, userId, requestDto.getRole());
    }

    @PatchMapping("/{userId}/enabled")
    public UserInfoResponseDto setEnabled(
            @AuthenticationPrincipal JwtUserPrincipal principal,
            @PathVariable Long userId,
            @Valid @RequestBody UpdateEnabledRequestDto requestDto
    ) {
        return adminService.setEnabled(principal, userId, requestDto.getEnabled());
    }

    @PostMapping("/{userId}/unlock")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void unlock(@AuthenticationPrincipal JwtUserPrincipal principal, @PathVariable Long userId) {
        adminService.unlock(principal, userId);
    }
}
