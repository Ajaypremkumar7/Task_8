package com.example.authapp.service;

import com.example.authapp.dto.AuthResponse;
import com.example.authapp.dto.LoginRequest;
import com.example.authapp.dto.RegisterRequest;
import com.example.authapp.entity.RefreshToken;
import com.example.authapp.entity.Role;
import com.example.authapp.entity.User;
import com.example.authapp.entity.VerificationToken; 
import com.example.authapp.entity.BlacklistedToken;
import com.example.authapp.exception.CustomException;
import com.example.authapp.repository.RefreshTokenRepository;
import com.example.authapp.repository.UserRepository;
import com.example.authapp.repository.VerificationTokenRepository; 
import com.example.authapp.repository.BlacklistedTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository; 
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final EmailService emailService; 
    private final UserService userService;
    private final TwoFactorAuthService twoFactorAuthService;

    @Lazy
    private final AuthenticationManager authenticationManager;

    private String generateToken() {
        return "refresh_token_" + new Random().nextInt(999999);
    }

    // ==================== HELPER: CREATE OR UPDATE REFRESH TOKEN ====================
    private RefreshToken createOrUpdateRefreshToken(User user, long expirySeconds) {
        String newTokenStr = generateToken();
        Optional<RefreshToken> existingTokenOpt = refreshTokenRepository.findByUser(user);

        RefreshToken refreshToken;
        if (existingTokenOpt.isPresent()) {
            refreshToken = existingTokenOpt.get();
            refreshToken.setToken(newTokenStr);
            refreshToken.setExpiryDate(Instant.now().plusSeconds(expirySeconds));
        } else {
            refreshToken = RefreshToken.builder()
                    .user(user)
                    .token(newTokenStr)
                    .expiryDate(Instant.now().plusSeconds(expirySeconds))
                    .build();
        }

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        System.out.println("Saved refresh token for user: " + user.getEmail() + " token: " + saved.getToken());
        return saved;
    }

    // ==================== REGISTER ====================
    public User register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new CustomException("User with this email already exists.");
        }

        Role assignedRole;
        try {
            assignedRole = Role.valueOf(request.getRole().toUpperCase());
        } catch (Exception e) {
            assignedRole = Role.USER;
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(assignedRole) 
                .enabled(false) 
                .build();
        userRepository.save(user);

        VerificationToken verificationToken = VerificationToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusSeconds(600))
                .build();
        verificationTokenRepository.save(verificationToken);

        try {
            emailService.sendVerificationEmail(user.getEmail(), verificationToken.getToken());
        } catch (Exception e) {
            System.out.println("Warning: Failed to send verification email: " + e.getMessage());
        }

        return user;
    }

    // ==================== LOGIN (CREDENTIALS) with 2FA and ACCOUNT LOCKOUT ====================
    @Transactional(noRollbackFor = CustomException.class)
    public AuthResponse login(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // ====== CHECK ACCOUNT LOCK ======
        if (user.isAccountLocked()) {
            if (user.getLockTime() != null && Instant.now().isAfter(user.getLockTime().plusSeconds(900))) { // 15 min lock
                user.setAccountLocked(false);
                user.setFailedLoginAttempts(0);
                user.setLockTime(null);
                userRepository.save(user);
            } else {
                long remainingSeconds = 0;
                if (user.getLockTime() != null) {
                    remainingSeconds = 900 - (Instant.now().getEpochSecond() - user.getLockTime().getEpochSecond());
                }
                throw new CustomException("Account is locked. Try again in " + remainingSeconds + " seconds.");
            }
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            // ====== RESET FAILED ATTEMPTS ON SUCCESS ======
            user.setFailedLoginAttempts(0);
            userRepository.save(user);

        } catch (Exception e) {
            // ====== INCREMENT FAILED ATTEMPTS ======
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            if (attempts >= 5) { // lock after 5 failed attempts
                user.setAccountLocked(true);
                user.setLockTime(Instant.now());
                // Send email notification
                try {
                    emailService.sendAccountLockEmail(user.getEmail(), 15); // 15 minutes lock
                } catch (Exception ex) {
                    System.out.println("Failed to send account lock email: " + ex.getMessage());
                }
            }

            userRepository.save(user);
            throw new CustomException("Invalid credentials. Attempt " + attempts + "/5");
        }

        if (user.isTwoFactorEnabled()) {
            if (request.getTotpCode() == null) {
                throw new CustomException("TOTP code required for 2FA");
            }
            boolean verified = twoFactorAuthService.verifyCode(user, request.getTotpCode().toString());
            if (!verified) {
                throw new CustomException("Invalid TOTP code");
            }
        }

        return generateTokens(user);
    }

    // ==================== LOGOUT ====================
    @Transactional
    public void logout(User user, String token) {
        User persistentUser = userRepository.findById(user.getId())
                .orElseThrow(() -> new CustomException("User not found"));

        // Remove refresh token
        refreshTokenRepository.findByUser(persistentUser)
                .ifPresent(refreshTokenRepository::delete);

        // ------------------- BLACKLIST PROVIDED ACCESS TOKEN -------------------
        if (token != null && !token.isEmpty()) {
            BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                    .token(token)
                    .expiryDate(Instant.now().plusSeconds(3600))
                    .build();
            blacklistedTokenRepository.save(blacklistedToken);
        }
    }

    // ==================== REFRESH TOKEN ====================
    @Transactional
    public AuthResponse refreshToken(String refreshTokenStr) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new CustomException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new CustomException("Refresh token expired. Please log in again.");
        }

        String newAccessToken = jwtService.generateToken(refreshToken.getUser());
        return new AuthResponse(newAccessToken, refreshToken.getToken());
    }

    // ==================== OAUTH2 LOGIN ====================
    @Transactional
    public AuthResponse loginWithOAuth2(String email, String username) {
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .username(username)
                            .email(email)
                            .role(Role.USER) 
                            .enabled(true)
                            .password(passwordEncoder.encode("default_password"))
                            .build();
                    return userRepository.save(newUser);
                });

        return generateTokens(user);
    }

    // ==================== GET USER BY EMAIL ====================
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found with email: " + email));
    }

    // ==================== AUTHENTICATE USER ====================
    public User authenticateUser(String email, String password) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );

        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // ==================== GENERATE TOKENS ====================
    public AuthResponse generateTokens(User user) {
        System.out.println("Generating tokens for user: " + user.getEmail());
        String accessToken = jwtService.generateToken(user);
        System.out.println("AccessToken: " + accessToken);
        RefreshToken refreshToken = createOrUpdateRefreshToken(user, 604800);
        System.out.println("RefreshToken: " + refreshToken.getToken());
        return new AuthResponse(accessToken, refreshToken.getToken());
    }

    // ==================== GET CURRENT AUTHENTICATED USER ====================
    public User getCurrentUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) return null;

        Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails userDetails) {
            return userRepository.findByEmail(userDetails.getUsername())
                    .orElseThrow(() -> new CustomException("User not found"));
        } else if (principal instanceof OAuth2User oauth2User) {
            String email = oauth2User.getAttribute("email");
            if (email != null) {
                return userRepository.findByEmail(email)
                        .orElseThrow(() -> new CustomException("User not found"));
            }
        }

        return null;
    }

    // ==================== GET EMAIL SERVICE ====================
    public EmailService getEmailService() {
        return emailService;
    }

    // ==================== VERIFY ACCOUNT ====================
    public Optional<VerificationToken> getVerificationTokenByUser(User user) {
        return verificationTokenRepository.findByUser(user);
    }

    // ==================== HELPER: VERIFY 2FA CODE ====================
    public boolean verify2FACode(User user, int totpCode) {
        return twoFactorAuthService.verifyCode(user, String.valueOf(totpCode));
    }

    // ==================== HELPER: GET USER FROM TOKEN ====================
    public User getCurrentUserFromToken(String token) {
        String email = jwtService.extractUsername(token);
        return userRepository.findByEmail(email).orElse(null);
    }
}
