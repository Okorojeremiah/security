package com.semicolonafrica.security.service;

import com.semicolonafrica.security.request.AuthenticationRequest;
import com.semicolonafrica.security.response.AuthenticationResponse;
import com.semicolonafrica.security.request.RegistrationRequest;
import com.semicolonafrica.security.user.Role;
import com.semicolonafrica.security.user.User;
import com.semicolonafrica.security.user.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegistrationRequest request) {
        var user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(),
                        request.getPassword()));
     var user = repository.findByEmail(request.getEmail())
             .orElseThrow();
     var jwtToken = jwtService.generateToken(user);
     return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
