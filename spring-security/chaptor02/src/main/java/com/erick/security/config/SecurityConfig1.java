package com.erick.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * security简单测试
 * @author You
 * @Date 2024/7/13 18:53
 */
//@Configuration
//@EnableWebSecurity
public class SecurityConfig1 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //报403
//        http.authorizeRequests(req->req.antMatchers("/api/greeting").hasRole("ADMIN"));
        //登录后即可访问
        http
                .formLogin(Customizer.withDefaults())
                .authorizeRequests(authorizeRequests -> authorizeRequests.antMatchers("/api/greeting")
                        .authenticated());
    }
}
