package com.coachini.authservice.controller;

import com.coachini.authservice.dto.AuthDtos;
import com.coachini.authservice.dto.AuthDtos.*;
import com.coachini.authservice.service.FirebaseAuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final FirebaseAuthService authService;

    public AuthController(FirebaseAuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthDtos.RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(req));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req) {
        return ResponseEntity.ok(authService.login(req));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest req) {
        return ResponseEntity.ok(authService.resetPassword(req));
    }

    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> me(@RequestHeader(value = "Authorization", required = false) String auth) {
        return ResponseEntity.ok(authService.verifyToken(auth));
    }
}
