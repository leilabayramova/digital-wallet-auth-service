package com.example.digitalwalletauthservice.service;

public interface NotificationService {

    void sendEmailVerification(String email, String token);

    void sendPasswordReset(String email, String token);
}
