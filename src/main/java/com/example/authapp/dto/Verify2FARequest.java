package com.example.authapp.dto;

import lombok.Data;

@Data
public class Verify2FARequest {
    private String email;
    private String code;
}
