package com.example.authapp.controller;

import com.example.authapp.entity.User;
import com.example.authapp.service.AuthService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class OAuth2UserController {

    private final AuthService authService; 

    @GetMapping("/user/oauth2")
    public String getUserInfo(@AuthenticationPrincipal OAuth2User oauth2User) {
        if (oauth2User != null) {
            String name = oauth2User.getAttribute("name");
            String email = oauth2User.getAttribute("email");
            
            System.out.println("OAuth2 User logged in:");
            System.out.println("Name: " + name);
            System.out.println("Email: " + email);
            
            return "Hello, " + name + "! You are logged in via OAuth2.";
        }

        User currentUser = authService.getCurrentUser(); 
        if (currentUser != null) {
            return "Hello, " + currentUser.getUsername() + "! You are logged in via JWT.";
        }

        return "Not authenticated.";
    }
}
