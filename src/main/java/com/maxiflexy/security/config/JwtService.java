package com.maxiflexy.security.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KET = "aIwgXPoi/M+eUWkwibeZPykjQoHDvvSphiSsP0lEaBMuallpQd+rFbNk6fo2MNS8K+LaFEzy46ch6+0zVnXulX+LgJ3LVxtyx+3NGczvmbtbwI4KKhmHmdnJO5vmLgPAcoAT925213sagbBzDa1EtPT9HVd7VirlJaDNOcDKb3AtJ98AX4xBIltnzIBrTan9e1Qbs04byDGZ8sBbKDDiJXVW5WkjHDyKEpFbXyRUeL7DE8ME4XH82CKAwNSk8lYyYd7D3lBZwusyBXnuqQEtxPx/or9ir934Gs14BJhVjCA7p5B0c3Yl1KIXolR0pOOpZPNUhHQX5hX4hnrojwhDBEt6NGcnp6JEab4r/cGTHd0=";


    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails){
        return Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userEmail = extractUsername(token);
        return userEmail.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
