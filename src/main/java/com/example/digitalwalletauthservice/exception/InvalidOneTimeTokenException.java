package com.example.digitalwalletauthservice.exception;

public class InvalidOneTimeTokenException extends RuntimeException {

    public InvalidOneTimeTokenException(String message) {
        super(message);
    }
}
