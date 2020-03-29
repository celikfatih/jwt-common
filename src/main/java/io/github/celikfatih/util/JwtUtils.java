package io.github.celikfatih.util;

import io.github.celikfatih.client.UserServiceClient;
import io.github.celikfatih.properties.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.function.Function;

/**
 * author @ fati
 * created @ 29.03.2020
 */

@Component
public class JwtUtils {

    private final JwtProperties jwtProperties;
    private final UserServiceClient userServiceClient;

    public JwtUtils(JwtProperties jwtProperties, UserServiceClient userServiceClient) {
        this.jwtProperties = jwtProperties;
        this.userServiceClient = userServiceClient;
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userServiceClient.getUser(extractUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private String getToken(HttpServletRequest request) {
        return request.getHeader(jwtProperties.getHeader());
    }

    public String getTokenWithoutBearer(HttpServletRequest request) {
        return StringUtils.isEmpty(getToken(request)) ? null : getToken(request).substring(7);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(getSigningKey()).parseClaimsJws(token).getBody();
    }

    private Key getSigningKey() {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(jwtProperties.getSecretKey());
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }

}
