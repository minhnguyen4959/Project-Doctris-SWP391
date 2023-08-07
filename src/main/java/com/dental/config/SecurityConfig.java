package com.dental.config;


import com.dental.entity.User;
import com.dental.service.UserDetailsServiceImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private HttpSession session;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        return new UserDetailsServiceImpl();
    }

    @Autowired
    UserDetailsServiceImpl userDetailsServiceImpl;

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        //set UserDetailsServiceImpl
        authenticationProvider.setUserDetailsService(userDetailsService());
        //set BCryptPasswordEncoder
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        System.out.println(authenticationProvider);
//        System.out.println(authenticationProvider.authenticate());
        return authenticationProvider;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http.csrf().disable()
                .authorizeHttpRequests()
                    .requestMatchers("/", "blog/**", "service/**", "doctor/**", "/register/**", "assets/**", "/forgot_password/**", "/reset_password/**", "/check_token/**", "/check_email/**").permitAll() // Allowing access to home page and static assets without authentication
                    .requestMatchers("/checkEmailExists").permitAll() // Allowing access to home page and static assets without authentication
                    .requestMatchers("/appointment/medical/**").hasAuthority("Doctor")
                    .requestMatchers("/admin/**").hasAnyAuthority("Admin", "Staff") // Require Staff authority for admin pages
                    .requestMatchers("/admin/user/**").hasAuthority("Admin") // Require ADMIN authority for admin pages
                .requestMatchers("/*").authenticated()
                .anyRequest().authenticated() // Require authentication for other URLs
                .and()
                    .formLogin()
                    .loginPage("/login")
                    .usernameParameter("email")
                    .passwordParameter("password")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("/redirect", true)
                    .failureUrl("/login?success=fail")
                    .permitAll()
                .and()
                    .logout()
                    .logoutUrl("/doLogout")
                    .logoutSuccessUrl("/logout-success")
                    .permitAll()
                .and()
                    .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                .and()
                .build();
    }


}
