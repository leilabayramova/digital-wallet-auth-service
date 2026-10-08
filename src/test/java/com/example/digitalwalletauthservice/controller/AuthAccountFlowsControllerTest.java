package com.example.digitalwalletauthservice.controller;

import com.example.digitalwalletauthservice.config.SecurityConfig;
import com.example.digitalwalletauthservice.dto.LoginRequestDto;
import com.example.digitalwalletauthservice.dto.RegisterRequestDto;
import com.example.digitalwalletauthservice.exception.AccountDisabledException;
import com.example.digitalwalletauthservice.exception.AccountLockedException;
import com.example.digitalwalletauthservice.exception.InvalidOneTimeTokenException;
import com.example.digitalwalletauthservice.exception.InvalidPasswordException;
import com.example.digitalwalletauthservice.exception.UserServiceRejectedException;
import com.example.digitalwalletauthservice.exception.UserServiceUnavailableException;
import com.example.digitalwalletauthservice.security.JwtService;
import com.example.digitalwalletauthservice.service.AuthService;
import com.example.digitalwalletauthservice.service.EmailVerificationService;
import com.example.digitalwalletauthservice.service.PasswordService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthAccountFlowsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private PasswordService passwordService;

    @MockitoBean
    private EmailVerificationService emailVerificationService;

    @MockitoBean
    private JwtService jwtService;

    private void authenticateAs(long userId, String role) {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(String.valueOf(userId));
        when(claims.get("email", String.class)).thenReturn("leila@example.com");
        when(claims.get("role", String.class)).thenReturn(role);

        when(jwtService.parseAccessToken("good-token")).thenReturn(claims);
    }

    @Test
    void register_shouldReturn400_whenPasswordHasNoDigit() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("onlyletters");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Password must contain at least one letter and one digit"));
    }

    @Test
    void register_shouldReturn400_whenBodyIsMalformedJson() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void register_shouldReturn503_whenUserServiceIsUnavailable() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        when(authService.register(any())).thenThrow(new UserServiceUnavailableException("unavailable"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void register_shouldReturn409_whenUserServiceReportsConflict() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        when(authService.register(any())).thenThrow(new UserServiceRejectedException(409, "rejected"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isConflict());
    }

    @Test
    void register_shouldReturn500WithGenericMessage_whenUnexpectedErrorOccurs() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        when(authService.register(any())).thenThrow(new IllegalStateException("secret internal detail"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("An unexpected error occurred"));
    }

    @Test
    void login_shouldReturn423_whenAccountIsLocked() throws Exception {
        LoginRequestDto requestDto = new LoginRequestDto();
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        when(authService.login(any())).thenThrow(new AccountLockedException("Account is temporarily locked"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isLocked());
    }

    @Test
    void login_shouldReturn403_whenAccountIsDisabled() throws Exception {
        LoginRequestDto requestDto = new LoginRequestDto();
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        when(authService.login(any())).thenThrow(new AccountDisabledException("Account is disabled"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isForbidden());
    }

    @Test
    void logout_shouldReturn204_withoutAuthentication() throws Exception {
        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"raw-refresh-token\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void logoutAll_shouldReturn401_whenNotAuthenticated() throws Exception {
        mockMvc.perform(post("/auth/logout-all")).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAll_shouldReturn204_whenAuthenticated() throws Exception {
        authenticateAs(1L, "USER");

        mockMvc.perform(post("/auth/logout-all").header("Authorization", "Bearer good-token"))
                .andExpect(status().isNoContent());
    }

    @Test
    void changePassword_shouldReturn401_whenNotAuthenticated() throws Exception {
        mockMvc.perform(post("/auth/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"old12345\",\"newPassword\":\"newPass123\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_shouldReturn204_whenAuthenticated() throws Exception {
        authenticateAs(1L, "USER");

        mockMvc.perform(post("/auth/change-password")
                        .header("Authorization", "Bearer good-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"old12345\",\"newPassword\":\"newPass123\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void changePassword_shouldReturn400_whenCurrentPasswordIsWrong() throws Exception {
        authenticateAs(1L, "USER");
        doThrow(new InvalidPasswordException("Current password is incorrect"))
                .when(passwordService).changePassword(eq(1L), any());

        mockMvc.perform(post("/auth/change-password")
                        .header("Authorization", "Bearer good-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"wrong1234\",\"newPassword\":\"newPass123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Current password is incorrect"));
    }

    @Test
    void forgotPassword_shouldReturn202_withoutAuthentication() throws Exception {
        mockMvc.perform(post("/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"leila@example.com\"}"))
                .andExpect(status().isAccepted());
    }

    @Test
    void resetPassword_shouldReturn204_whenTokenIsValid() throws Exception {
        mockMvc.perform(post("/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"abc\",\"newPassword\":\"newPass123\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void resetPassword_shouldReturn400_whenTokenIsInvalid() throws Exception {
        doThrow(new InvalidOneTimeTokenException("Token is invalid or has expired"))
                .when(passwordService).resetPassword(any());

        mockMvc.perform(post("/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"abc\",\"newPassword\":\"newPass123\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyEmail_shouldReturn204() throws Exception {
        mockMvc.perform(post("/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"abc\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void resendVerification_shouldReturn202_whenAuthenticated() throws Exception {
        authenticateAs(1L, "USER");

        mockMvc.perform(post("/auth/resend-verification").header("Authorization", "Bearer good-token"))
                .andExpect(status().isAccepted());
    }

    @Test
    void unknownEndpoint_shouldReturn401_whenNotAuthenticated() throws Exception {
        mockMvc.perform(get("/does-not-exist")).andExpect(status().isUnauthorized());
    }
}
