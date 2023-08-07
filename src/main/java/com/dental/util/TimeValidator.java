package com.dental.util;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.sql.Time;

public class TimeValidator implements ConstraintValidator<TimeConstraint, Time> {
    @Override
    public boolean isValid(Time time, ConstraintValidatorContext context) {
        if (time == null) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Time is mandatory")
                    .addConstraintViolation();
            return false;
        }

        return true;
    }
}