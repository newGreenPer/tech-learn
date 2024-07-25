package com.erick.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.var;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Map;


/**
 * 成功登录/失败登录定制
 * @author You
 * @Date 2024/7/20 11:33
 */
//@EnableWebSecurity
public class SecurityConfig4 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(req -> req.antMatchers("/api/greeting").authenticated())
                .httpBasic(Customizer.withDefaults())
                .formLogin(form -> form.loginPage("/login")
                        .successHandler(getCommonAuthenticationSuccessHandler())
                        .failureHandler(getCommonAuthenticationFailureHandler())
                )
                .csrf(AbstractHttpConfigurer::disable);
    }


    /**
     * 认证失败信息
     * @return
     */
    public static AuthenticationFailureHandler getCommonAuthenticationFailureHandler() {
        return (request, response, exception) -> {
            var objectMapper = new ObjectMapper();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            var errData = Map.of(
                    "title", "认证失败",
                    "detail", exception.getMessage()
            );
            response.getWriter().println(objectMapper.writeValueAsString(errData));
        };
    }

    /**
     *认证成功信息
     * @return
     */
    public static AuthenticationSuccessHandler getCommonAuthenticationSuccessHandler() {
        return (request, response, authentication) -> {
            ObjectMapper objectMapper = new ObjectMapper();
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().println(objectMapper.writeValueAsString(authentication));
        };
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().mvcMatchers("/public/**")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user")
                .password(passwordEncoder().encode("12345678"))
                .roles("ADMIN", "USER");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
