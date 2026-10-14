package com.coachini.authservice.service;

import com.coachini.authservice.dto.AuthDtos.*;
import com.coachini.authservice.exception.AuthException;
import com.google.firebase.auth.AuthErrorCode;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.google.firebase.auth.UserRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Service
public class FirebaseAuthService {

    private static final String BASE = "https://identitytoolkit.googleapis.com/v1/accounts";

    private final FirebaseAuth firebaseAuth;
    private final RestClient restClient = RestClient.create();
    private final String apiKey;

    public FirebaseAuthService(FirebaseAuth firebaseAuth,
                               @Value("${firebase.api-key}") String apiKey) {
        this.firebaseAuth = firebaseAuth;
        this.apiKey = apiKey;
    }

    // ---------- REGISTER ----------
    public RegisterResponse register(RegisterRequest req) {
        try {
            UserRecord.CreateRequest createRequest = new UserRecord.CreateRequest()
                    .setEmail(req.email())
                    .setPassword(req.password())
                    .setEmailVerified(false);
            if (req.displayName() != null && !req.displayName().isBlank()) {
                createRequest.setDisplayName(req.displayName());
            }
            UserRecord user = firebaseAuth.createUser(createRequest);
            return new RegisterResponse(user.getUid(), user.getEmail(), user.getDisplayName());
        } catch (FirebaseAuthException e) {
            if (e.getAuthErrorCode() == AuthErrorCode.EMAIL_ALREADY_EXISTS) {
                throw new AuthException(HttpStatus.CONFLICT, "Email already registered");
            }
            throw new AuthException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    // ---------- LOGIN ----------
    public LoginResponse login(LoginRequest req) {
        try {
            FirebaseSignInResponse res = restClient.post()
                    .uri(BASE + ":signInWithPassword?key=" + apiKey)
                    .body(Map.of("email", req.email(),
                            "password", req.password(),
                            "returnSecureToken", true))
                    .retrieve()
                    .body(FirebaseSignInResponse.class);

            return new LoginResponse(res.localId(), res.email(), res.idToken(),
                    res.refreshToken(), res.expiresIn());
        } catch (HttpClientErrorException e) {
            String code = extractFirebaseError(e);
            switch (code) {
                case "EMAIL_NOT_FOUND", "INVALID_PASSWORD", "INVALID_LOGIN_CREDENTIALS" ->
                        throw new AuthException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
                case "USER_DISABLED" ->
                        throw new AuthException(HttpStatus.FORBIDDEN, "Account disabled");
                default -> throw new AuthException(HttpStatus.BAD_REQUEST, code);
            }
        }
    }

    // ---------- RESET PASSWORD ----------
    public MessageResponse resetPassword(ResetPasswordRequest req) {
        try {
            restClient.post()
                    .uri(BASE + ":sendOobCode?key=" + apiKey)
                    .body(Map.of("requestType", "PASSWORD_RESET", "email", req.email()))
                    .retrieve()
                    .toBodilessEntity();
        } catch (HttpClientErrorException e) {
            String code = extractFirebaseError(e);
            if (!"EMAIL_NOT_FOUND".equals(code)) {
                throw new AuthException(HttpStatus.BAD_REQUEST, code);
            }
            // EMAIL_NOT_FOUND is swallowed on purpose: don't reveal which emails exist
        }
        return new MessageResponse("If this email is registered, a reset link has been sent");
    }

    // ---------- VERIFY TOKEN ----------
    public UserInfoResponse verifyToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Missing bearer token");
        }
        try {
            FirebaseToken token = firebaseAuth.verifyIdToken(authorizationHeader.substring(7), true);
            return new UserInfoResponse(token.getUid(), token.getEmail(), token.getName());
        } catch (FirebaseAuthException e) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        }
    }

    @SuppressWarnings("unchecked")
    private String extractFirebaseError(HttpClientErrorException e) {
        try {
            Map<String, Object> body = e.getResponseBodyAs(Map.class);
            if (body != null && body.get("error") instanceof Map<?, ?> err
                    && err.get("message") instanceof String msg) {
                return msg.split(" ")[0]; // "WEAK_PASSWORD : ..." -> "WEAK_PASSWORD"
            }
        } catch (Exception ignored) {
        }
        return "UNKNOWN_ERROR";
    }
}