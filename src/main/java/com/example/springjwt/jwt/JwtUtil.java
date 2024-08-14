package com.example.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private SecretKey secretKey;

    //미리 저장해둔 String키를 기반으로 객체 키 생성
    public JwtUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //유저네임 가져오기
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    //롤값 가져오기
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    //카테고리 가져오기
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    //토큰 소멸 여부
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    //토큰 생성
    public String createJwt(String category, String username, String role, Long expiredMs) {
        return Jwts.builder()
                //키에 대한 데이터
                .claim("category", category)
                .claim("username", username)
                .claim("role", role)
                //현재 발행 시간
                .issuedAt(new Date(System.currentTimeMillis()))
                //언제 소멸 될 것인지
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                //키를 통해 암호화 진행
                .signWith(secretKey)
                .compact();
    }

}
