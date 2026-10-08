package com.example.digitalwalletauthservice.controller;

import com.example.digitalwalletauthservice.config.SecurityConfig;
import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.InvalidOperationException;
import com.example.digitalwalletauthservice.exception.UserNotFoundException;
import com.example.digitalwalletauthservice.security.JwtService;
import com.example.digitalwalletauthservice.service.AdminService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminController.class)
@Import(SecurityConfig.class)
class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminService adminService;

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
    void updateRole_shouldReturn401_whenNotAuthenticated() throws Exception {
        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateRole_shouldReturn403_whenCallerIsNotAdmin() throws Exception {
        authenticateAs(1L, "USER");

        mockMvc.perform(patch("/admin/users/5/role")
                        .header("Authorization", "Bearer good-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void updateRole_shouldReturn200_whenCallerIsAdmin() throws Exception {
        authenticateAs(1L, "ADMIN");
        when(adminService.updateRole(any(), eq(5L), eq(Role.ADMIN)))
                .thenReturn(UserInfoResponseDto.builder().userId(5L).email("a@example.com").role(Role.ADMIN).build());

        mockMvc.perform(patch("/admin/users/5/role")
                        .header("Authorization", "Bearer good-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void updateRole_shouldReturn400_whenRoleIsMissing() throws Exception {
        authenticateAs(1L, "ADMIN");

        mockMvc.perform(patch("/admin/users/5/role")
                        .header("Authorization", "Bearer good-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void setEnabled_shouldReturn400_whenAdminTargetsThemselves() throws Exception {
        authenticateAs(1L, "ADMIN");
        when(adminService.setEnabled(any(), eq(1L), eq(false)))
                .thenThrow(new InvalidOperationException("Administrators cannot change their own role or status"));

        mockMvc.perform(patch("/admin/users/1/enabled")
                        .header("Authorization", "Bearer good-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unlock_shouldReturn404_whenUserDoesNotExist() throws Exception {
        authenticateAs(1L, "ADMIN");
        org.mockito.Mockito.doThrow(new UserNotFoundException("User not found"))
                .when(adminService).unlock(any(), eq(99L));

        mockMvc.perform(post("/admin/users/99/unlock").header("Authorization", "Bearer good-token"))
                .andExpect(status().isNotFound());
    }

    @Test
    void unlock_shouldReturn204_whenCallerIsAdmin() throws Exception {
        authenticateAs(1L, "ADMIN");

        mockMvc.perform(post("/admin/users/5/unlock").header("Authorization", "Bearer good-token"))
                .andExpect(status().isNoContent());
    }
}
