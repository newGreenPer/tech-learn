package com.erick.security.validation;

import lombok.var;
import com.erick.security.validation.annotation.ValidEmail;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

/**
 * @author You
 * @Date 2024/8/10 12:31
 */
public class EmailValidator implements ConstraintValidator<ValidEmail, String> {

    private static final String pattern_regex = "^[A-Za-z0-9\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";

    @Override
    public void initialize(ValidEmail constraintAnnotation) {

    }

    @Override
    public boolean isValid(String s, ConstraintValidatorContext constraintValidatorContext) {
        return match(s);
    }

    private boolean match(final String email) {
        var pattern = Pattern.compile(pattern_regex);
        var match = pattern.matcher(email);
        return match.matches();
    }
}
