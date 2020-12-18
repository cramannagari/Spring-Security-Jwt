package com.springSecurity.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.springSecurity.jwt.model.AuthenticateRequest;
import com.springSecurity.jwt.model.AuthenticateResponse;
import com.springSecurity.jwt.util.JwtUtil;

@RestController
public class Resouces {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtUtil jwtUtilBean;

	@RequestMapping("/test")
	public String hello() {
		return "Hello World";
	}

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticateToken(@RequestBody AuthenticateRequest authenticateRequest)
			throws Exception {

		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticateRequest.getUserName(), authenticateRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new Exception("Incorrect userName and password", e);
		}

		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticateRequest.getUserName());
		final String jwt = jwtUtilBean.generateToken(userDetails);

		return ResponseEntity.ok(new AuthenticateResponse(jwt));

	}
}
