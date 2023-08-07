package com.dental.util;

import com.dental.util.AgeConstraint;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.sql.Date;
import java.time.LocalDate;
import java.time.Period;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

public class AgeValidator implements ConstraintValidator<AgeConstraint, java.sql.Date> {
    @Override
    public boolean isValid(java.sql.Date dateOfBirth, ConstraintValidatorContext context) {
        if (dateOfBirth == null) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Date of birth is required")
                    .addConstraintViolation();
            return false;
        }

        LocalDate birthDate = dateOfBirth.toLocalDate();
        LocalDate currentDate = LocalDate.now();
        Period age = Period.between(birthDate, currentDate);

        return age.getYears() >= 20;
    }
}