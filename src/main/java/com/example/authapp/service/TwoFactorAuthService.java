package com.example.authapp.service;

import com.example.authapp.entity.TwoFactorAuth;
import com.example.authapp.entity.User;
import com.example.authapp.repository.TwoFactorAuthRepository;
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private final TwoFactorAuthRepository twoFactorAuthRepository;
    private final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
    private final Base32 base32 = new Base32();

    // Generate secret key 
    public String generateAndSaveSecretKey(User user) {
        return twoFactorAuthRepository.findByUser(user).map(existing -> {
            if (!existing.isEnabled()) {
                existing.setEnabled(true);
                twoFactorAuthRepository.save(existing);
            }
            return existing.getSecret();
        }).orElseGet(() -> {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());
                keyGenerator.init(160);
                SecretKey secretKey = keyGenerator.generateKey();
                String encoded = base32.encodeToString(secretKey.getEncoded());

                TwoFactorAuth twoFactor = TwoFactorAuth.builder()
                        .user(user)
                        .secret(encoded)
                        .enabled(true)
                        .build();
                twoFactorAuthRepository.save(twoFactor);

                return encoded;
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate 2FA secret key", e);
            }
        });
    }

    // Verify by Authenticator Code
    public boolean verifyCode(User user, String codeStr) {
        return twoFactorAuthRepository.findByUser(user).map(twoFactor -> {
            try {
                byte[] decoded = base32.decode(twoFactor.getSecret());
                SecretKey key = new SecretKeySpec(decoded, totp.getAlgorithm());

                int code = Integer.parseInt(codeStr);

                return generateTOTPCode(key) == code;
            } catch (NumberFormatException e) {
                return false;
            }
        }).orElse(false);
    }

    public int generateTOTPCode(SecretKey key) {
        try {
            return totp.generateOneTimePassword(key, Instant.now());
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Failed to generate TOTP", e);
        }
    }

    // Secret key as Object
    public SecretKey getSecretKey(User user) {
        return twoFactorAuthRepository.findByUser(user)
                .map(twoFactor -> {
                    byte[] decoded = base32.decode(twoFactor.getSecret());
                    return new SecretKeySpec(decoded, totp.getAlgorithm());
                })
                .orElse(null);
    }
}
