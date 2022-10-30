package com.aegisep.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

/**
 * JWT token 발행 및 Parsing
 */
@Component
public class JwToken {

    private final Key key;
    private final int expire;

    public JwToken(@Value("${jwt.secret}") String secrat, @Value("${jwt.expire}") int expire) {
        this.key = Keys.hmacShaKeyFor(secrat.getBytes(StandardCharsets.UTF_8));
        this.expire = expire;
    }
    /* 토큰 생성 payload 여기에 추가 */
    public String createToken(String sub, Map<String, Object> claims) {
        return Jwts.builder()
                .setSubject(sub)
                .addClaims(claims)
                .setExpiration(Date.from(Instant.now().plus(expire, ChronoUnit.MINUTES)))
                .signWith(key)
                .compact();
    }

    public Map<String, Object> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
