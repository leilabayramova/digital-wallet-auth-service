package com.example.digitalwalletauthservice.controller;

import com.example.digitalwalletauthservice.dto.AuthResponseDto;
import com.example.digitalwalletauthservice.dto.LoginRequestDto;
import com.example.digitalwalletauthservice.dto.RefreshRequestDto;
import com.example.digitalwalletauthservice.dto.RegisterRequestDto;
import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.EmailAlreadyExistsException;
import com.example.digitalwalletauthservice.exception.InvalidCredentialsException;
import com.example.digitalwalletauthservice.exception.InvalidRefreshTokenException;
import com.example.digitalwalletauthservice.config.SecurityConfig;
import com.example.digitalwalletauthservice.security.JwtService;
import com.example.digitalwalletauthservice.service.AuthService;
import com.example.digitalwalletauthservice.service.EmailVerificationService;
import com.example.digitalwalletauthservice.service.PasswordService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private PasswordService passwordService;

    @MockitoBean
    private EmailVerificationService emailVerificationService;

    private AuthResponseDto sampleAuthResponse() {
        return AuthResponseDto.builder()
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .tokenType("Bearer")
                .expiresInSeconds(900)
                .build();
    }

    @Test
    void register_shouldReturn201() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("john.doe@example.com");
        requestDto.setPassword("password123");

        when(authService.register(any())).thenReturn(sampleAuthResponse());

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value("access-token"));
    }

    @Test
    void register_shouldReturn400_whenPasswordTooShort() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("john.doe@example.com");
        requestDto.setPassword("short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_shouldReturn409_whenEmailAlreadyExists() throws Exception {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("john.doe@example.com");
        requestDto.setPassword("password123");

        when(authService.register(any()))
                .thenThrow(new EmailAlreadyExistsException("User already exists with email: john.doe@example.com"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isConflict());
    }

    @Test
    void login_shouldReturn200() throws Exception {
        LoginRequestDto requestDto = new LoginRequestDto();
        requestDto.setEmail("john.doe@example.com");
        requestDto.setPassword("password123");

        when(authService.login(any())).thenReturn(sampleAuthResponse());

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"));
    }

    @Test
    void login_shouldReturn401_whenCredentialsInvalid() throws Exception {
        LoginRequestDto requestDto = new LoginRequestDto();
        requestDto.setEmail("john.doe@example.com");
        requestDto.setPassword("wrong-password");

        when(authService.login(any()))
                .thenThrow(new InvalidCredentialsException("Invalid email or password"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_shouldReturn200() throws Exception {
        RefreshRequestDto requestDto = new RefreshRequestDto();
        requestDto.setRefreshToken("raw-refresh-token");

        when(authService.refresh(any())).thenReturn(sampleAuthResponse());

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    void refresh_shouldReturn401_whenTokenInvalid() throws Exception {
        RefreshRequestDto requestDto = new RefreshRequestDto();
        requestDto.setRefreshToken("bad-token");

        when(authService.refresh(any()))
                .thenThrow(new InvalidRefreshTokenException("Refresh token is invalid"));

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_shouldReturn400_whenRefreshTokenBlank() throws Exception {
        RefreshRequestDto requestDto = new RefreshRequestDto();
        requestDto.setRefreshToken(" ");

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getCurrentUser_shouldReturn401_whenNoAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getCurrentUser_shouldReturn401_whenTokenInvalid() throws Exception {
        when(jwtService.parseAccessToken("bad-token")).thenThrow(new JwtException("invalid signature"));

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer bad-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getCurrentUser_shouldReturn200_whenTokenValid() throws Exception {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("1");
        when(claims.get("email", String.class)).thenReturn("john.doe@example.com");
        when(claims.get("role", String.class)).thenReturn("USER");

        when(jwtService.parseAccessToken("good-token")).thenReturn(claims);
        when(authService.getCurrentUser(any())).thenReturn(
                UserInfoResponseDto.builder()
                        .userId(1L)
                        .email("john.doe@example.com")
                        .role(Role.USER)
                        .build()
        );

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer good-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("john.doe@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }
}
