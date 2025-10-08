package com.example.authapp.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserProfileDto {
    private String username;
    private String email;
    private String profilePictureUrl;
}
