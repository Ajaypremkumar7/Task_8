package com.example.authapp.service;

import com.example.authapp.entity.Role;
import com.example.authapp.entity.User;
import com.example.authapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        String email = null;
        String name = null;
        
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
    
        System.out.println("Received attributes from " + registrationId + ": " + oauth2User.getAttributes());
        
        if ("github".equals(registrationId)) {
            name = (String) oauth2User.getAttributes().get("login");
            email = (String) oauth2User.getAttributes().get("email");
            
            if (email == null) {
                throw new OAuth2AuthenticationException("GitHub email not found or is private.");
            }
        } else if ("google".equals(registrationId)) {
            name = (String) oauth2User.getAttributes().get("name");
            email = (String) oauth2User.getAttributes().get("email");

            if (email == null) {
                throw new OAuth2AuthenticationException("Google email not found.");
            }
        }
        
        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isEmpty()) {
            User newUser = User.builder()
                .username(name)
                .email(email)
                .role(Role.USER)
                .enabled(true)
                .build();
            userRepository.save(newUser);
        } else {
            User user = existingUser.get();
            user.setUsername(name);
            userRepository.save(user);
        }

        return oauth2User;
    }
}