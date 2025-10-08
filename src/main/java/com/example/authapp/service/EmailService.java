package com.example.authapp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

   
    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }

    public void sendVerificationEmail(String email, String token) {
        String subject = "Account Verification";
        String verificationUrl = "http://localhost:8080/api/auth/verify?token=" + token;
        String text = "Thank you for registering. Please click the link below to verify your email address:\n" + verificationUrl;
        sendEmail(email, subject, text);
    }

    // ==================== SEND ACCOUNT LOCK EMAIL ====================
    public void sendAccountLockEmail(String email, int lockMinutes) {
        String subject = "Account Locked";
        String text = "Your account has been locked due to multiple failed login attempts. "
                    + "It will be unlocked automatically after " + lockMinutes + " minutes.";
        sendEmail(email, subject, text);
    }
}
