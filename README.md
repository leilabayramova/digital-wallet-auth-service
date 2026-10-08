# Digital Wallet Auth Service

Authentication and authorization microservice of the Digital Wallet system. It provides registration, login, JWT
access tokens with rotating refresh tokens, password management, email verification and admin operations.

- **Port:** `9093`
- **Depends on:** `user-service` (`http://localhost:9091`), which stores the user profile created at registration
- **Database:** PostgreSQL (`digital_wallet_auth_db`), schema managed by Liquibase

## Tech stack

Java 17 · Spring Boot 4.1.1 · Spring Security · Spring Data JPA · PostgreSQL · Liquibase · JJWT 0.12.6 ·
OpenFeign · Resilience4j (circuit breaker) · Actuator · springdoc-openapi · Testcontainers

## Requirements

- JDK 17
- Docker (for PostgreSQL and for the integration tests)
- A running `user-service` (needed for registration and for creating the first admin)

## Running locally

1. Start PostgreSQL and create the database:

   ```bash
   docker run -d --name postgres-db -e POSTGRES_PASSWORD=1234 -p 5432:5432 postgres:16
   docker exec postgres-db psql -U postgres -c "CREATE DATABASE digital_wallet_auth_db;"
   ```

   You do not need to create tables: Liquibase applies the migrations on the first start.

2. Start `user-service` on port `9091`.

3. Start the application (the default profile is `local`):

   ```bash
   ./gradlew bootRun
   ```

The `local` profile (`application-local.yaml`) holds the database password and a development JWT secret for local
use only. Never use those values in any other environment.

Swagger UI: `http://localhost:9093/swagger-ui.html` · Health check: `http://localhost:9093/actuator/health`

## Configuration

| Property | Environment variable | Default | Description |
|---|---|---|---|
| `jwt.secret` | `JWT_SECRET` | none (required) | At least 32 characters. The application refuses to start if it is blank or too short |
| `jwt.access-token-expiration-ms` | | `900000` (15 min) | Access token lifetime |
| `jwt.refresh-token-expiration-ms` | | `604800000` (7 days) | Refresh token lifetime |
| `jwt.issuer` / `jwt.audience` | | `digital-wallet-auth-service` / `digital-wallet` | Token claims, both are verified on parsing |
| `auth.max-failed-login-attempts` | | `5` | Failed logins before the account is locked |
| `auth.lock-duration-minutes` | | `15` | Lock duration |
| `auth.password-reset-ttl-minutes` | | `30` | Password reset token lifetime |
| `auth.email-verification-ttl-minutes` | | `1440` | Email verification token lifetime |
| `auth.require-email-verification` | | `false` | If `true`, login is refused until the email is verified |
| `auth.cleanup-retention-days` | | `7` | Age after which stale tokens are purged |
| `auth.cleanup-cron` | | `0 0 3 * * *` | Schedule of the cleanup job |
| `auth.bootstrap-admin.email` | `BOOTSTRAP_ADMIN_EMAIL` | empty | If set, the first admin is created at startup |
| `auth.bootstrap-admin.password` | `BOOTSTRAP_ADMIN_PASSWORD` | empty | Password of the first admin |
| `clients.user-service.url` | | `http://localhost:9091` | Address of `user-service` |

## API

All error responses share the same format:

```json
{ "status": 409, "message": "User already exists with email: leila@example.com", "timestamp": "2026-10-05T12:00:00" }
```

### Authentication (`/auth`)

| Method | Path | Access | Success | Notes |
|---|---|---|---|---|
| POST | `/auth/register` | public | 201 + tokens | Creates the profile in `user-service` |
| POST | `/auth/login` | public | 200 + tokens | |
| POST | `/auth/refresh` | public | 200 + new tokens | The used refresh token is revoked |
| POST | `/auth/logout` | public | 204 | Revokes the given refresh token |
| POST | `/auth/logout-all` | Bearer | 204 | Revokes every session of the user |
| GET | `/auth/me` | Bearer | 200 | `userId`, `email` and `role` from the token |
| POST | `/auth/change-password` | Bearer | 204 | Revokes every session |
| POST | `/auth/forgot-password` | public | 202 | Same response whether or not the email is registered |
| POST | `/auth/reset-password` | public | 204 | Uses a single-use token |
| POST | `/auth/verify-email` | public | 204 | Uses a single-use token |
| POST | `/auth/resend-verification` | Bearer | 202 | |

### Admin (`/admin/users`, `ADMIN` role only)

| Method | Path | Body |
|---|---|---|
| PATCH | `/admin/users/{userId}/role` | `{ "role": "ADMIN" }` |
| PATCH | `/admin/users/{userId}/enabled` | `{ "enabled": false }` |
| POST | `/admin/users/{userId}/unlock` | none |

An admin cannot change their own role or status.

### Examples

```bash
# Register
curl -X POST http://localhost:9093/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"fullName":"Leila","email":"leila@example.com","password":"Passw0rd123"}'

# Log in
curl -X POST http://localhost:9093/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"leila@example.com","password":"Passw0rd123"}'

# Current user
curl http://localhost:9093/auth/me -H 'Authorization: Bearer <accessToken>'
```

Token response:

```json
{ "accessToken": "...", "refreshToken": "...", "tokenType": "Bearer", "expiresInSeconds": 900 }
```

### Status codes

| Code | Cases |
|---|---|
| 400 | Validation error, malformed JSON, wrong current password, invalid single-use token |
| 401 | Wrong email or password, invalid or revoked refresh token, missing or invalid access token |
| 403 | Account disabled, email not verified, insufficient role |
| 404 | User not found (admin operations) |
| 409 | Email already registered |
| 423 | Account temporarily locked |
| 502 / 503 | `user-service` returned an unexpected response / is unavailable |

## Security model

- **Passwords** are stored with BCrypt. Rules: 8 to 72 characters, at least one letter and one digit.
- **Access token:** JWT signed with HMAC-SHA (`iss`, `aud`, `jti`, `sub`, `email`, `role`). The algorithm is chosen
  by the secret length: HS256 for 32-47 bytes, HS384 for 48-63, HS512 for 64 or more. Other services verify it with
  the same secret and must require the same `iss` and `aud`.
- **Refresh token:** random value; only its SHA-256 hash is stored. It is rotated on every use.
- **Theft detection:** if an already revoked refresh token is presented again, every session of that user is revoked.
- **Brute-force protection:** consecutive failed logins lock the account temporarily. A password comparison is also
  performed for unknown emails so response time does not reveal whether an account exists.
- **Single-use tokens** (password reset, email verification) are stored only as hashes, consumed atomically, and a
  newly issued token invalidates the earlier ones.
- **Audit:** the `AUDIT` logger records the event and the `userId`; it never logs emails, passwords or tokens.
- **When a role or status changes,** the user's refresh tokens are revoked. An access token that was already issued
  (15 minutes at most) stays valid with the old data.

## Resilience

- Calls to `user-service` go through a Resilience4j circuit breaker. 4xx answers from `user-service` do not open the
  breaker; unavailability results in a 503.
- The registration idempotency key is derived from the email, so retrying a half-finished registration is safe.
- `register()` never holds a database transaction open while calling another service.

## Email delivery

No email provider is integrated yet. In the `local` profile single-use tokens are written to the log (`[DEV ONLY]`).
In other profiles the message is not delivered and a warning is logged. For real use, implement the
`NotificationService` interface with SMTP or an email API.

## Tests

```bash
./gradlew test
```

- Unit and controller tests (Mockito, `@WebMvcTest`).
- Integration tests run against a real PostgreSQL 16 container through Testcontainers (Liquibase migrations
  included), so **Docker must be running**. Concurrent refresh and concurrent registration scenarios are covered.

## Project structure

```
src/main/java/com/example/digitalwalletauthservice
├── client       UserServiceClient (Feign), UserProfileGateway (circuit breaker)
├── config       SecurityConfig, JwtProperties, AuthProperties, Clock
├── controller   AuthController, AdminController
├── dto          request and response objects
├── entity       CredentialEntity, RefreshTokenEntity, OneTimeTokenEntity
├── exception    exceptions and GlobalExceptionHandler
├── mapper       AuthMapper
├── repository   JPA repositories
├── security     JwtService, JwtAuthenticationFilter
└── service      AuthService, TokenService, PasswordService, EmailVerificationService,
                 AdminService, OneTimeTokenService, TokenCleanupJob, AdminBootstrap, notification services
src/main/resources
├── application.yaml, application-local.yaml
└── liquibase/changes   migrations 001 to 005
```

## Before going to production

For IE staff: consult IE Cloud Services to validate the infrastructure design before deploying.
