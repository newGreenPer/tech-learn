package com.erick.security.config;

import com.erick.security.config.dsl.ClientErrorLoggingConfigurer;
import com.erick.security.filter.RestAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.var;
import org.passay.MessageResolver;
import org.passay.spring.SpringMessageResolver;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import java.util.ArrayList;
import java.util.Map;

import static com.erick.security.config.SecurityConfig4.getCommonAuthenticationFailureHandler;
import static com.erick.security.config.SecurityConfig4.getCommonAuthenticationSuccessHandler;

/** /authorize/login和登录页 共存
 * 两个用户，两种密码编码
 * @author You
 * @Date 2024/7/27 18:28
 */
//@EnableWebSecurity(debug = true)
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig6 extends WebSecurityConfigurerAdapter {

    private final ObjectMapper objectMapper;
    private final MessageSource messageSource;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(a -> a.antMatchers("/authorize/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").hasRole("USER")
                .anyRequest().authenticated())
                .addFilterAt(usernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .csrf(csrf -> csrf.ignoringAntMatchers("/authorize/**", "/admin/**", "/api/**"))
                .formLogin(form -> form.loginPage("/login")
                        .usernameParameter("username1")
                        .defaultSuccessUrl("/")
                        .successHandler(getCommonAuthenticationSuccessHandler())
                        .failureHandler(getCommonAuthenticationFailureHandler())
                        .permitAll())
                .logout(logout -> logout.logoutUrl("/perform_logout")
                        .logoutSuccessHandler(jsonLogoutSuccessHandler())
                )
                .rememberMe(r -> r.tokenValiditySeconds(86400))
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{bcrypt}$2a$10$t7Oqdz24UBeeByV4TQtzWuCWotowxZ5LfmiUXB5rEq8ljGVXg7d2y")
                .roles("USERS", "ADMIN")
                .and()
                .withUser("zhangsan")
                .password("{SHA-1}{gl4A2YfSPOyBAos8SeiWkU/X6R/CxdAeQZgecclbJ9Q=}427dda99c374000b8f3841b3ac810de6775bc098")
                .roles("USERS", "ADMIN")
        ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().mvcMatchers("/public/**")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
        ;
    }

    @Bean
    LogoutSuccessHandler jsonLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            if (authentication != null && authentication.getDetails() != null) {
                request.getSession().invalidate();
            }
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().println();
            log.info("成功退出登录");
        };
    }

    @Bean
    public ClientErrorLoggingConfigurer clientErrorLogging() {
        return new ClientErrorLoggingConfigurer(new ArrayList<>());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        var idForDefault = "bcrypt";
        var encoders = Map.of(
                idForDefault, new BCryptPasswordEncoder(),
                "SHA-1", new MessageDigestPasswordEncoder("SHA-1")
        );
        return new DelegatingPasswordEncoder(idForDefault, encoders);
    }

    @Bean
    RestAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        RestAuthenticationFilter restAuthenticationFilter = new RestAuthenticationFilter(objectMapper);
        restAuthenticationFilter.setAuthenticationSuccessHandler(getCommonAuthenticationSuccessHandler());
        restAuthenticationFilter.setAuthenticationFailureHandler(getCommonAuthenticationFailureHandler());
        restAuthenticationFilter.setAuthenticationManager(authenticationManager());
        restAuthenticationFilter.setFilterProcessesUrl("/authorize/login");
        return restAuthenticationFilter;
    }

}
