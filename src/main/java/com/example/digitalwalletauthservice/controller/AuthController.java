package com.example.digitalwalletauthservice.controller;

import com.example.digitalwalletauthservice.dto.AuthResponseDto;
import com.example.digitalwalletauthservice.dto.ChangePasswordRequestDto;
import com.example.digitalwalletauthservice.dto.ForgotPasswordRequestDto;
import com.example.digitalwalletauthservice.dto.LoginRequestDto;
import com.example.digitalwalletauthservice.dto.LogoutRequestDto;
import com.example.digitalwalletauthservice.dto.RefreshRequestDto;
import com.example.digitalwalletauthservice.dto.RegisterRequestDto;
import com.example.digitalwalletauthservice.dto.ResetPasswordRequestDto;
import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.dto.VerifyEmailRequestDto;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;
import com.example.digitalwalletauthservice.service.AuthService;
import com.example.digitalwalletauthservice.service.EmailVerificationService;
import com.example.digitalwalletauthservice.service.PasswordService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final PasswordService passwordService;
    private final EmailVerificationService emailVerificationService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthResponseDto register(@Valid @RequestBody RegisterRequestDto requestDto) {
        return authService.register(requestDto);
    }

    @PostMapping("/login")
    public AuthResponseDto login(@Valid @RequestBody LoginRequestDto requestDto) {
        return authService.login(requestDto);
    }

    @PostMapping("/refresh")
    public AuthResponseDto refresh(@Valid @RequestBody RefreshRequestDto requestDto) {
        return authService.refresh(requestDto);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody LogoutRequestDto requestDto) {
        authService.logout(requestDto);
    }

    @PostMapping("/logout-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logoutAll(@AuthenticationPrincipal JwtUserPrincipal principal) {
        authService.logoutAll(principal);
    }

    @GetMapping("/me")
    public UserInfoResponseDto getCurrentUser(@AuthenticationPrincipal JwtUserPrincipal principal) {
        return authService.getCurrentUser(principal);
    }

    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            @AuthenticationPrincipal JwtUserPrincipal principal,
            @Valid @RequestBody ChangePasswordRequestDto requestDto
    ) {
        passwordService.changePassword(principal.userId(), requestDto);
    }

    @PostMapping("/forgot-password")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void forgotPassword(@Valid @RequestBody ForgotPasswordRequestDto requestDto) {
        passwordService.forgotPassword(requestDto);
    }

    @PostMapping("/reset-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(@Valid @RequestBody ResetPasswordRequestDto requestDto) {
        passwordService.resetPassword(requestDto);
    }

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void verifyEmail(@Valid @RequestBody VerifyEmailRequestDto requestDto) {
        emailVerificationService.verify(requestDto);
    }

    @PostMapping("/resend-verification")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void resendVerification(@AuthenticationPrincipal JwtUserPrincipal principal) {
        emailVerificationService.resend(principal.userId());
    }
}
