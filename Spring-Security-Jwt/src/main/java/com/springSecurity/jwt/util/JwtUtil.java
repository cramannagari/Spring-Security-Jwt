package com.springSecurity.jwt.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.cglib.core.internal.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {

	private String SECRET_KEY = "secret";

	public String generateToken(UserDetails userDetails) {

		Map<String, Object> cliams = new HashMap<>();

		return createToken(cliams, userDetails.getUsername());

	}

	private String createToken(Map<String, Object> cliams, String subject) {

		return Jwts.builder().setClaims(cliams).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}

	public <T> T extractClaim(String token, Function<Claims, T> cliamsResolver) {

		final Claims claims = extractAllCliams(token);

		return cliamsResolver.apply(claims);

	}

	private Claims extractAllCliams(String token) {

		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}

	private boolean isTokenExpried(String token) {

		return extractExpiration(token).before(new Date());
	}

	public Date extractExpiration(String token) {

		return extractClaim(token, Claims::getExpiration);
	}

	public Boolean validateToken(String token, UserDetails userDetails) {

		final String username = extractUserName(token);

		return (username.equals(userDetails.getUsername()) && !isTokenExpried(token));

	}

	public String extractUserName(String token) {

		return extractClaim(token, Claims::getSubject);
	}
}
