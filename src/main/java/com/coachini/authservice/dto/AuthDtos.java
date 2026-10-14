package com.coachini.authservice.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;


public class AuthDtos {

    public record RegisterRequest(
            @NotBlank @Email String email,
            @NotBlank @Size(min = 6, message = "Password must be at least 6 characters") String password,
            String displayName) {}

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password) {}

    public record ResetPasswordRequest(
            @NotBlank @Email String email) {}

    public record RegisterResponse(String uid, String email, String displayName) {}

    public record LoginResponse(String uid, String email, String idToken,
                                String refreshToken, String expiresIn) {}

    public record MessageResponse(String message) {}

    public record UserInfoResponse(String uid, String email, String name) {}

    // Firebase REST API payloads
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FirebaseSignInResponse(String localId, String email, String idToken,
                                         String refreshToken, String expiresIn) {}
}