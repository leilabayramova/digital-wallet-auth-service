package com.example.digitalwalletauthservice;

import com.example.digitalwalletauthservice.client.UserProfileGateway;
import com.example.digitalwalletauthservice.dto.CreateUserRequestDto;
import com.example.digitalwalletauthservice.dto.UserProfileResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.UserServiceUnavailableException;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import com.example.digitalwalletauthservice.repository.RefreshTokenRepository;
import com.example.digitalwalletauthservice.service.NotificationService;
import com.example.digitalwalletauthservice.support.PostgresIntegrationTest;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class AuthFlowIntegrationTest extends PostgresIntegrationTest {

    private static final String PASSWORD = "Passw0rd123";
    private static final AtomicLong USER_IDS = new AtomicLong(1000);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private UserProfileGateway userProfileGateway;

    @MockitoBean
    private NotificationService notificationService;

    @BeforeEach
    void setUp() {
        when(userProfileGateway.createUser(any(CreateUserRequestDto.class), anyString())).thenAnswer(invocation -> {
            UserProfileResponseDto profile = new UserProfileResponseDto();
            profile.setId(USER_IDS.incrementAndGet());

            return profile;
        });
    }

    // ---------- helpers ----------

    private String newEmail() {
        return "leila-" + UUID.randomUUID() + "@example.com";
    }

    private MvcResult postJson(String path, String json) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json)).andReturn();
    }

    private MvcResult postJson(String path, String json, String accessToken) throws Exception {
        return mockMvc.perform(post(path)
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json)).andReturn();
    }

    private MvcResult register(String email) throws Exception {
        return postJson("/auth/register",
                "{\"fullName\":\"Leila\",\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}");
    }

    private MvcResult login(String email, String password) throws Exception {
        return postJson("/auth/login", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}");
    }

    private MvcResult refresh(String refreshToken) throws Exception {
        return postJson("/auth/refresh", "{\"refreshToken\":\"" + refreshToken + "\"}");
    }

    private String json(MvcResult result, String path) throws Exception {
        return JsonPath.read(result.getResponse().getContentAsString(), path);
    }

    private CredentialEntity createAdmin() {
        return credentialRepository.save(CredentialEntity.builder()
                .userId(USER_IDS.incrementAndGet())
                .email(newEmail())
                .passwordHash(passwordEncoder.encode(PASSWORD))
                .role(Role.ADMIN)
                .emailVerified(true)
                .build());
    }

    // ---------- tests ----------

    @Test
    void contextLoads_andLiquibaseCreatedTheSchema() {
        assertThat(credentialRepository.count()).isGreaterThanOrEqualTo(0);
        assertThat(refreshTokenRepository.count()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void healthEndpoint_shouldBePublic() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void registerLoginMeRefresh_fullFlow() throws Exception {
        String email = newEmail();

        MvcResult registered = register(email);
        assertThat(registered.getResponse().getStatus()).isEqualTo(201);

        MvcResult loggedIn = login(email.toUpperCase(), PASSWORD);
        assertThat(loggedIn.getResponse().getStatus()).isEqualTo(200);

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer " + json(loggedIn, "$.accessToken")))
                .andExpect(status().isOk());

        MvcResult refreshed = refresh(json(loggedIn, "$.refreshToken"));
        assertThat(refreshed.getResponse().getStatus()).isEqualTo(200);
        assertThat(json(refreshed, "$.refreshToken")).isNotEqualTo(json(loggedIn, "$.refreshToken"));
    }

    @Test
    void register_shouldReturn409_forDuplicateEmail() throws Exception {
        String email = newEmail();

        assertThat(register(email).getResponse().getStatus()).isEqualTo(201);
        assertThat(register(email).getResponse().getStatus()).isEqualTo(409);
    }

    @Test
    void register_shouldReturn503_whenUserServiceIsDown() throws Exception {
        when(userProfileGateway.createUser(any(), anyString()))
                .thenThrow(new UserServiceUnavailableException("down"));

        assertThat(register(newEmail()).getResponse().getStatus()).isEqualTo(503);
    }

    @Test
    void register_shouldSendVerificationMessage() throws Exception {
        String email = newEmail();

        register(email);

        verify(notificationService).sendEmailVerification(eq(email), anyString());
    }

    @Test
    void refreshTokenReuse_shouldRevokeEveryActiveSession() throws Exception {
        String email = newEmail();
        register(email);

        MvcResult first = login(email, PASSWORD);
        MvcResult second = login(email, PASSWORD);

        String firstRefresh = json(first, "$.refreshToken");
        MvcResult rotated = refresh(firstRefresh);
        assertThat(rotated.getResponse().getStatus()).isEqualTo(200);

        // replay of the already rotated token => theft suspected
        assertThat(refresh(firstRefresh).getResponse().getStatus()).isEqualTo(401);

        // all other sessions, including the freshly rotated one, are gone
        assertThat(refresh(json(rotated, "$.refreshToken")).getResponse().getStatus()).isEqualTo(401);
        assertThat(refresh(json(second, "$.refreshToken")).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void concurrentRefreshWithSameToken_shouldSucceedExactlyOnce() throws Exception {
        String email = newEmail();
        register(email);
        String refreshToken = json(login(email, PASSWORD), "$.refreshToken");

        int threads = 4;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            List<Future<Integer>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Callable<Integer> task = () -> {
                    start.await();
                    return refresh(refreshToken).getResponse().getStatus();
                };
                futures.add(executor.submit(task));
            }

            start.countDown();

            long successes = 0;
            for (Future<Integer> future : futures) {
                if (future.get() == 200) {
                    successes++;
                }
            }

            assertThat(successes).isEqualTo(1);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void concurrentRegistrationWithSameEmail_shouldCreateExactlyOneAccount() throws Exception {
        String email = newEmail();

        int threads = 4;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            List<Future<Integer>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    return register(email).getResponse().getStatus();
                }));
            }

            start.countDown();

            long created = 0;
            for (Future<Integer> future : futures) {
                int statusCode = future.get();
                assertThat(statusCode).isIn(201, 409);
                if (statusCode == 201) {
                    created++;
                }
            }

            assertThat(created).isEqualTo(1);
            assertThat(credentialRepository.existsByEmail(email)).isTrue();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void logout_shouldRevokeTheRefreshToken() throws Exception {
        String email = newEmail();
        register(email);
        String refreshToken = json(login(email, PASSWORD), "$.refreshToken");

        assertThat(postJson("/auth/logout", "{\"refreshToken\":\"" + refreshToken + "\"}")
                .getResponse().getStatus()).isEqualTo(204);

        assertThat(refresh(refreshToken).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void logoutAll_shouldRevokeEverySession() throws Exception {
        String email = newEmail();
        register(email);

        MvcResult first = login(email, PASSWORD);
        MvcResult second = login(email, PASSWORD);

        assertThat(postJson("/auth/logout-all", "{}", json(first, "$.accessToken"))
                .getResponse().getStatus()).isEqualTo(204);

        assertThat(refresh(json(first, "$.refreshToken")).getResponse().getStatus()).isEqualTo(401);
        assertThat(refresh(json(second, "$.refreshToken")).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void login_shouldLockAccountAfterTooManyFailures_andAdminCanUnlock() throws Exception {
        String email = newEmail();
        register(email);

        for (int i = 0; i < 3; i++) {
            assertThat(login(email, "WrongPass1").getResponse().getStatus()).isEqualTo(401);
        }

        // even the correct password is refused while locked
        assertThat(login(email, PASSWORD).getResponse().getStatus()).isEqualTo(423);

        CredentialEntity admin = createAdmin();
        String adminToken = json(login(admin.getEmail(), PASSWORD), "$.accessToken");
        Long userId = credentialRepository.findByEmail(email).orElseThrow().getUserId();

        assertThat(postJson("/admin/users/" + userId + "/unlock", "{}", adminToken)
                .getResponse().getStatus()).isEqualTo(204);

        assertThat(login(email, PASSWORD).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void passwordReset_fullFlow() throws Exception {
        String email = newEmail();
        register(email);
        String oldRefresh = json(login(email, PASSWORD), "$.refreshToken");

        postJson("/auth/forgot-password", "{\"email\":\"" + email + "\"}");

        var tokenCaptor = forClass(String.class);
        verify(notificationService, atLeastOnce()).sendPasswordReset(eq(email), tokenCaptor.capture());
        String resetToken = tokenCaptor.getValue();

        assertThat(postJson("/auth/reset-password",
                "{\"token\":\"" + resetToken + "\",\"newPassword\":\"BrandNew123\"}")
                .getResponse().getStatus()).isEqualTo(204);

        assertThat(login(email, "BrandNew123").getResponse().getStatus()).isEqualTo(200);
        assertThat(login(email, PASSWORD).getResponse().getStatus()).isEqualTo(401);
        assertThat(refresh(oldRefresh).getResponse().getStatus()).isEqualTo(401);

        // single use
        assertThat(postJson("/auth/reset-password",
                "{\"token\":\"" + resetToken + "\",\"newPassword\":\"AnotherNew123\"}")
                .getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void forgotPassword_shouldRespondTheSameForUnknownEmail() throws Exception {
        assertThat(postJson("/auth/forgot-password", "{\"email\":\"" + newEmail() + "\"}")
                .getResponse().getStatus()).isEqualTo(202);
    }

    @Test
    void changePassword_shouldRequireCurrentPasswordAndRevokeSessions() throws Exception {
        String email = newEmail();
        register(email);
        MvcResult session = login(email, PASSWORD);
        String accessToken = json(session, "$.accessToken");

        assertThat(postJson("/auth/change-password",
                "{\"currentPassword\":\"Wrong12345\",\"newPassword\":\"BrandNew123\"}", accessToken)
                .getResponse().getStatus()).isEqualTo(400);

        assertThat(postJson("/auth/change-password",
                "{\"currentPassword\":\"" + PASSWORD + "\",\"newPassword\":\"BrandNew123\"}", accessToken)
                .getResponse().getStatus()).isEqualTo(204);

        assertThat(refresh(json(session, "$.refreshToken")).getResponse().getStatus()).isEqualTo(401);
        assertThat(login(email, "BrandNew123").getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void emailVerification_fullFlow() throws Exception {
        String email = newEmail();
        register(email);

        var tokenCaptor = forClass(String.class);
        verify(notificationService).sendEmailVerification(eq(email), tokenCaptor.capture());

        assertThat(credentialRepository.findByEmail(email).orElseThrow().isEmailVerified()).isFalse();

        assertThat(postJson("/auth/verify-email", "{\"token\":\"" + tokenCaptor.getValue() + "\"}")
                .getResponse().getStatus()).isEqualTo(204);

        assertThat(credentialRepository.findByEmail(email).orElseThrow().isEmailVerified()).isTrue();

        assertThat(postJson("/auth/verify-email", "{\"token\":\"" + tokenCaptor.getValue() + "\"}")
                .getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void disabledUser_cannotLoginOrRefresh_andAdminChecksAreEnforced() throws Exception {
        String email = newEmail();
        register(email);
        MvcResult session = login(email, PASSWORD);
        Long userId = credentialRepository.findByEmail(email).orElseThrow().getUserId();

        // a regular user is not allowed to use the admin API
        assertThat(mockMvc.perform(patch("/admin/users/" + userId + "/enabled")
                        .header("Authorization", "Bearer " + json(session, "$.accessToken"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andReturn().getResponse().getStatus()).isEqualTo(403);

        CredentialEntity admin = createAdmin();
        String adminToken = json(login(admin.getEmail(), PASSWORD), "$.accessToken");

        assertThat(mockMvc.perform(patch("/admin/users/" + userId + "/enabled")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andReturn().getResponse().getStatus()).isEqualTo(200);

        assertThat(login(email, PASSWORD).getResponse().getStatus()).isEqualTo(403);
        assertThat(refresh(json(session, "$.refreshToken")).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void admin_cannotChangeOwnRole() throws Exception {
        CredentialEntity admin = createAdmin();
        String adminToken = json(login(admin.getEmail(), PASSWORD), "$.accessToken");

        assertThat(mockMvc.perform(patch("/admin/users/" + admin.getUserId() + "/role")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"USER\"}"))
                .andReturn().getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void malformedJson_shouldReturn400_notServerError() throws Exception {
        assertThat(postJson("/auth/login", "{oops").getResponse().getStatus()).isEqualTo(400);
    }
}
