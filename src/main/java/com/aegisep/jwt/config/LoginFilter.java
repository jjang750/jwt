package com.aegisep.jwt.config;

import com.aegisep.jwt.JwToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 로그인 후 token 발행
 */
@Component
@RequiredArgsConstructor
public class LoginFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final JwToken jwToken;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var username = request.getHeader("username");
        var password = request.getHeader("password");

        var authenticated = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        response.setHeader(HttpHeaders.AUTHORIZATION, createJwToken(authenticated));
    }
    /* 로그인 인증 처리 된 사용자 정보를 이용하여 토큰 발행 */
    private String createJwToken(Authentication authenticated) {
        var user = (User) authenticated.getPrincipal();
        var roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return jwToken.createToken(user.getUsername(), Map.of("roles", roles));

    }
    /**
     * Request 정보를 분석하여 filter 사용여부 체크
     * Return 값은 false가 기본
     *  */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        var method = request.getMethod();
        var uri = request.getRequestURI();
        var isLogin = HttpMethod.POST.matches(method) && uri.startsWith("/login");
        return !isLogin;
    }
}
