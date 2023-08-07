package com.dental.util;

import com.dental.util.DateConstraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.sql.Date;
import java.time.LocalDate;

public class DateValidator implements ConstraintValidator<DateConstraint, Date> {
    @Override
    public boolean isValid(Date date, ConstraintValidatorContext context) {
        if (date == null) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Date is mandatory")
                    .addConstraintViolation();
            return false;
        }

        LocalDate currentDate = LocalDate.now();
        LocalDate selectedDate = date.toLocalDate();

        if (selectedDate.isBefore(currentDate)) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Date cannot be in the past")
                    .addConstraintViolation();
            return false;
        }

        return true;
    }
}