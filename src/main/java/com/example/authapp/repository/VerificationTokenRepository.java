package com.example.authapp.repository;

import com.example.authapp.entity.VerificationToken;
import com.example.authapp.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByToken(String token); 

    Optional<VerificationToken> findByUser(User user);
}
