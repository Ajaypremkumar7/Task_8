package com.example.authapp.controller;

import com.example.authapp.dto.*;
import com.example.authapp.entity.User;
import com.example.authapp.entity.VerificationToken;
import com.example.authapp.service.AuthService;
import com.example.authapp.service.PasswordService;
import com.example.authapp.service.TwoFactorAuthService;
import com.example.authapp.service.UserService;
import com.example.authapp.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;

import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TwoFactorAuthService twoFactorAuthService;
    private final UserService userService;
    private final VerificationTokenRepository verificationTokenRepository; 
    private final PasswordService passwordService; 

    // ---------------- Register ----------------
    @PostMapping("/register")
    public ResponseEntity<UserResponseDto> register(@RequestBody RegisterRequest request) {
        User user = authService.register(request);
        UserResponseDto dto = new UserResponseDto(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    // ---------------- Email Verification ----------------
    @GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        User user = verificationToken.getUser();
        user.setEnabled(true);
        userService.updateProfile(user, user.getUsername()); 
        verificationTokenRepository.delete(verificationToken); 

        return ResponseEntity.ok("Email verified successfully");
    }

    // ---------------- Login (Credentials) ----------------
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        User user = authService.getUserByEmail(request.getEmail());

        if (user.isTwoFactorEnabled()) {
            if (request.getTotpCode() == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthResponse(null, null));
            }
            boolean verified = twoFactorAuthService.verifyCode(user, String.valueOf(request.getTotpCode()));
            if (!verified) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthResponse(null, null));
            }
        }

        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    // ---------------- Enable 2FA ----------------
    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA(@RequestBody EmailRequest request) {
        User user = authService.getUserByEmail(request.getEmail());

        if (!user.isTwoFactorEnabled()) {
            String secretKey = twoFactorAuthService.generateAndSaveSecretKey(user);
            user.setTwoFactorEnabled(true);
            userService.updateProfile(user, user.getUsername());
            return ResponseEntity.ok("2FA enabled. Secret key: " + secretKey);
        }

        return ResponseEntity.ok("2FA already enabled for this user");
    }

    // ---------------- Verify 2FA ----------------
    @PostMapping("/verify-2fa")
    public ResponseEntity<AuthResponse> verify2FA(@RequestBody Verify2FARequest request) {
        User user = authService.getUserByEmail(request.getEmail());

        if (!user.isEnabled() || !user.isTwoFactorEnabled()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse(null, null));
        }

        boolean verified = twoFactorAuthService.verifyCode(user, String.valueOf(request.getCode()));

        if (!verified) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse(null, null));
        }

        AuthResponse response = authService.generateTokens(user);

        System.out.println("Generated accessToken: " + response.getAccessToken());
        System.out.println("Generated refreshToken: " + response.getRefreshToken());

        return ResponseEntity.ok(response);
    }

    // ---------------- Refresh Token ----------------
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    // ---------------- Logout ----------------
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader,
                                    @RequestBody(required = false) Verify2FARequest request) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7); // Extract JWT
        User user = authService.getCurrentUserFromToken(token);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }

        Integer totpCode = null;
        if (user.isTwoFactorEnabled()) {
            if (request == null || request.getCode() == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("TOTP code required");
            }
            try {
                totpCode = Integer.parseInt(request.getCode());
            } catch (NumberFormatException e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid TOTP code format");
            }
            boolean verified = authService.verify2FACode(user, totpCode);
            if (!verified) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("2FA verification failed");
            }
        }

        authService.logout(user, token); // Pass token to blacklist
        return ResponseEntity.ok("Logged out successfully");
    }

    // ---------------- Test Email Sending ----------------
    @PostMapping("/send-test-email")
    public ResponseEntity<String> sendTestEmail(@RequestBody EmailRequest request) {
        User user = authService.getUserByEmail(request.getEmail());

        VerificationToken verificationToken = authService.getVerificationTokenByUser(user)
                .orElseThrow(() -> new RuntimeException("No verification token found for this user"));

        authService.getEmailService().sendVerificationEmail(user.getEmail(), verificationToken.getToken());

        return ResponseEntity.ok("Test verification email sent");
    }

    // ---------------- Forgot Password ----------------
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody EmailRequest request) {
        passwordService.initiateForgotPassword(request.getEmail());
        return ResponseEntity.ok("Password reset link has been sent to your email");
    }

    // ---------------- Reset Password ----------------
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        passwordService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok("Password has been reset successfully");
    }

    // ---------------- Generate TOTP from secret key ----------------
    @PostMapping("/generate-totp")
    public ResponseEntity<String> generateTOTP(@RequestBody SecretKeyRequest request) {
        try {
            String secret = request.getSecret();
            byte[] decoded = Base64.getDecoder().decode(secret);
            SecretKey key = new SecretKeySpec(decoded, "HmacSHA1");
            int code = twoFactorAuthService.generateTOTPCode(key);
            return ResponseEntity.ok(String.format("%06d", code));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid secret key");
        }
    }
}
