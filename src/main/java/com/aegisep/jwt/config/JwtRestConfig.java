package com.aegisep.jwt.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class JwtRestConfig {

    @GetMapping("/")
    @PreAuthorize("hasRole('USER')")
    public String home() {
        return "welcome home";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String user() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("Username : {}, Roles: {}", authentication.getPrincipal(), authentication.getAuthorities());
        return "user home";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "admin home";
    }

}
