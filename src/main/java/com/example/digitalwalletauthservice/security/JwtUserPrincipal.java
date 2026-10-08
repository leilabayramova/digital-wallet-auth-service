package com.example.digitalwalletauthservice.security;

import com.example.digitalwalletauthservice.entity.Role;

public record JwtUserPrincipal(Long userId, String email, Role role) {
}
