package com.example.authapp.controller;

import com.example.authapp.dto.UserProfileDto;
import com.example.authapp.entity.User;
import com.example.authapp.repository.UserRepository;
import com.example.authapp.service.CloudinaryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/me")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final CloudinaryService cloudinaryService;

    // Get current user profile
    @GetMapping("/profile")
    public ResponseEntity<UserProfileDto> getProfile(Authentication authentication) {
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserProfileDto dto = UserProfileDto.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .profilePictureUrl(user.getProfilePictureUrl())
                .build();
        return ResponseEntity.ok(dto);
    }

    // Update username
    @PutMapping("/username")
    public ResponseEntity<UserProfileDto> updateProfile(Authentication authentication,
                                                        @RequestBody UserProfileDto dto) {
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (dto.getUsername() != null && !dto.getUsername().isEmpty()) {
            user.setUsername(dto.getUsername());
        }
        userRepository.save(user);

        UserProfileDto responseDto = UserProfileDto.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .profilePictureUrl(user.getProfilePictureUrl())
                .build();
        return ResponseEntity.ok(responseDto);
    }

    // Upload profile picture
    @PostMapping("/picture")
    public ResponseEntity<String> uploadPicture(Authentication authentication,
                                                @RequestParam("file") MultipartFile file) throws Exception {
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String url = cloudinaryService.uploadFile(file);
        user.setProfilePictureUrl(url);
        userRepository.save(user);
        return ResponseEntity.ok(url);
    }
}
