package com.erick.security.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * http请求 post方式、认证、授权 均采用默认
 * @author You
 * @Date 2024/7/13 21:38
 */
//@EnableWebSecurity(debug = true)
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(req->req.antMatchers("/api/greeting").authenticated())
                //Post方法 请求涉及csrf
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .formLogin(AbstractHttpConfigurer::disable)
                ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //配置静态资源
        web.ignoring().mvcMatchers("/public/**");
    }
}
