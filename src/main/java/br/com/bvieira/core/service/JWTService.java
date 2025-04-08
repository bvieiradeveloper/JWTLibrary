package br.com.bvieira.core.service;


import br.com.bvieira.core.dto.AuthUserResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

import static io.jsonwebtoken.lang.Objects.isEmpty;

public class JWTService {
    private static final String EMPTY_SPACE = " ";
    private static final int TOKEN_INDEX = 1;

    private final String secretKey;

    public JWTService(String secretKey) {
        this.secretKey = secretKey;
    }

    public AuthUserResponse getAuthenticatedUser(String token) throws Exception{
        var tokenClaims = getClaims(token);
        var userId = Integer.valueOf((String)tokenClaims.get("id"));
        return new AuthUserResponse(userId, (String)tokenClaims.get("username"));
    }

    private Claims getClaims(String token) throws Exception{
        var accessToken = extractToken(token);
        try{
            return Jwts.parser()
                    .verifyWith(generateSign())
                    .build()
                    .parseSignedClaims(accessToken)
                    .getPayload();

        } catch (Exception e) {
            throw new Exception("Invalid Token " + e.getMessage());
        }
    }

    public void validateAccessToken(String token) throws Exception {
        getClaims(token);
    }

    private SecretKey generateSign(){
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
    private String extractToken(String token) throws Exception {
        if (isEmpty(token)){
            throw new Exception("The access token was not informed.");
        }

        if (token.contains(EMPTY_SPACE)){
            return token.split(EMPTY_SPACE)[TOKEN_INDEX];
        }

        return  token;
    }
}
