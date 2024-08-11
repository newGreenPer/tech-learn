package com.erick.security.exception;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.zalando.problem.spring.web.advice.ProblemHandling;

/**
 * 异常信息链暑促
 * @author You
 * @Date 2024/8/10 16:49
 */
@ControllerAdvice
public class ExceptionHandler implements ProblemHandling {
    @Override
    public boolean isCausalChainsEnabled() {
        return true;
    }
}
