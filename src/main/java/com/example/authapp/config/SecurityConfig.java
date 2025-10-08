package com.example.authapp.config;

import com.example.authapp.config.OAuth2LoginSuccessHandler;
import com.example.authapp.security.RateLimitingFilter;
import com.example.authapp.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // <-- Added to enable @PreAuthorize
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final JwtService jwtService;
    private final RateLimitingFilter rateLimitingFilter;

    public SecurityConfig(@Lazy OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
                          JwtService jwtService,
                          RateLimitingFilter rateLimitingFilter) {
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.jwtService = jwtService;
        this.rateLimitingFilter = rateLimitingFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(
                    "/", "/index.html",
                    "/css/**", "/js/**", "/images/**", "/static/**",
                    "/oauth2/**",
                    "/api/auth/register",
                    "/api/auth/login",
                    "/api/auth/send-test-email",
                    "/api/auth/verify",
                    "/api/auth/forgot-password",
                    "/api/auth/reset-password",
                    "/api/auth/enable-2fa",
                    "/api/auth/verify-2fa",
                    "/api/auth/refresh-token",
                    "/api/auth/logout",
                    "/api/auth/generate-totp",
                    "/user/oauth2"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .successHandler(oAuth2LoginSuccessHandler)
            )
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setContentType("application/json");
                    response.setStatus(401);
                    response.getOutputStream().println("{ \"error\": \"" + authException.getMessage() + "\" }");
                })
                .accessDeniedHandler(accessDeniedHandler())
            );

        // Add RateLimitingFilter BEFORE JWT filter
        http.addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);

        // Add your custom JWT filter BEFORE UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtService.jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setContentType("application/json");
            response.setStatus(403);
            response.getOutputStream().println("{ \"error\": \"" + accessDeniedException.getMessage() + "\" }");
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
