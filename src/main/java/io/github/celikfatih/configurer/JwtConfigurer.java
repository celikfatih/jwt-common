package io.github.celikfatih.configurer;

import io.github.celikfatih.filter.JwtAuthenticationFilter;
import io.github.celikfatih.util.JwtUtils;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.util.function.Function;

/**
 * author @ fati
 * created @ 29.03.2020
 */

public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private JwtUtils jwtUtils;
    private final Function<String, UserDetails> userDetailsFunction;

    public JwtConfigurer(JwtUtils jwtUtils, Function<String, UserDetails> userDetailsFunction) {
        this.jwtUtils = jwtUtils;
        this.userDetailsFunction = userDetailsFunction;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint((request, response, e) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtils, userDetailsFunction), UsernamePasswordAuthenticationFilter.class);
    }
}
