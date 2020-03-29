package io.github.celikfatih.filter;

import io.github.celikfatih.util.JwtUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import java.util.function.Function;

/**
 * Authenticate request with header 'Authorization: Bearer {Token}'
 *
 * author @ fati
 * created @ 29.03.2020
 */

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final Function<String, UserDetails> userDetailsFunction;

    public JwtAuthenticationFilter(JwtUtils jwtUtils, Function<String, UserDetails> userDetailsFunction) {
        this.jwtUtils = jwtUtils;
        this.userDetailsFunction = userDetailsFunction;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = jwtUtils.resolveToken(httpServletRequest);
        if (StringUtils.hasText(token) && jwtUtils.verifyToken(token)) {
            Authentication authentication = jwtUtils.getAuthentication(token, userDetailsFunction);
            if (Objects.nonNull(authentication)) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }

    }
}
