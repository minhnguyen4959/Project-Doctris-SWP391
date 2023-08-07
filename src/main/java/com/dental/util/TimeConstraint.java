package com.dental.util;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({FIELD, METHOD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = TimeValidator.class)
@Documented
public @interface TimeConstraint {
    String message() default "Invalid time";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
