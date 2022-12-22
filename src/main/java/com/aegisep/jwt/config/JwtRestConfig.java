package com.aegisep.jwt.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class JwtRestConfig {
//
//    @GetMapping("/")
//    @PreAuthorize("hasRole('USER')")
//    public ResponseEntity<String> home() {
//        return ResponseEntity.ok("welcome home");
//    }

    @GetMapping(value ="/user", produces = "application/json; charset=UTF-8")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> user() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("Username : {}, Roles: {}", authentication.getPrincipal(), authentication.getAuthorities());
        return ResponseEntity.ok("user home");
    }

    @GetMapping(value ="/admin", produces = "application/json; charset=UTF-8")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("admin home");
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("health home");
    }

}
