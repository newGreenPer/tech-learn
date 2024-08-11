package com.erick.security.validation.annotation;

import com.erick.security.validation.EmailValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

/**
 * @author You
 * @Date 2024/8/10 12:29
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Constraint(validatedBy = EmailValidator.class)
@Documented
public @interface ValidEmail {

    String message() default "{ValidEmail.email}";

    Class<?>[] groups() default { };

    Class<? extends Payload>[] payload() default { };
}
