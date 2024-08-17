package com.erick.security.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


/**
 * 和SecurityConfig8配置 作为多个安全配置共存，注意order次序配置
 * @author You
 * @Date 2024/8/10 23:19
 */
@Order(100)
@Configuration
public class LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(req -> req.anyRequest().authenticated())
                // 设置无访问权限时，通过页面form表单登录的方式鉴权
                .formLogin(form -> form
                                .loginPage("/login")
                        .usernameParameter("username")
                        .failureUrl("/login?error")
                        .defaultSuccessUrl("/")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/perform_logout")
                        .logoutSuccessUrl("/login")
                )
                .rememberMe(r -> r.key("someSecret").tokenValiditySeconds(86400))
                .httpBasic(Customizer.withDefaults())
        ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/error")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{bcrypt}$2a$10$t7Oqdz24UBeeByV4TQtzWuCWotowxZ5LfmiUXB5rEq8ljGVXg7d2y")
                .roles("USER", "ADMIN")
                .and()
                .withUser("zhangsan")
                .password("{SHA-1}{gl4A2YfSPOyBAos8SeiWkU/X6R/CxdAeQZgecclbJ9Q=}427dda99c374000b8f3841b3ac810de6775bc098")
                .roles("USER", "ADMIN")
        ;
    }

}
