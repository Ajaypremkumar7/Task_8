package com.example.authapp.controller;

import com.example.authapp.dto.UserResponseDto;
import com.example.authapp.entity.User;
import com.example.authapp.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    // GET ALL USERS
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        List<UserResponseDto> users = adminService.getAllUsers().stream()
                .map(user -> new UserResponseDto(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getRole()
                ))
                .toList();

        return ResponseEntity.ok(users);
    }

    // REVOKE USER SESSIONS
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/sessions/revoke")
    public ResponseEntity<String> revokeSessions(@RequestBody RevokeSessionRequest request) {
        adminService.revokeUserSessions(request.getUserId());
        return ResponseEntity.ok("User sessions revoked successfully");
    }

    public static class RevokeSessionRequest {
        private Long userId;

        public Long getUserId() {
            return userId;
        }

        public void setUserId(Long userId) {
            this.userId = userId;
        }
    }
}
