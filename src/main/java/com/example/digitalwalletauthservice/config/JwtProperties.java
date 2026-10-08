package com.example.digitalwalletauthservice.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    @NotBlank(message = "jwt.secret must be provided (set the JWT_SECRET environment variable)")
    @Size(min = 32, message = "jwt.secret must be at least 32 characters long")
    private String secret;

    @Positive
    private long accessTokenExpirationMs;

    @Positive
    private long refreshTokenExpirationMs;

    @NotBlank
    private String issuer = "digital-wallet-auth-service";

    @NotBlank
    private String audience = "digital-wallet";
}
