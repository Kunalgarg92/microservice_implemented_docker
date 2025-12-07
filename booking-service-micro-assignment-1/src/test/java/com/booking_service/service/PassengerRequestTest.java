package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import com.booking_service.DTO.PassengerRequest;

import java.util.Set;

class PassengerRequestTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void testAllArgsConstructorAndEquals() {
        PassengerRequest p1 = new PassengerRequest("REGULAR", "John", "MALE", 22, "VEG", 10);
        PassengerRequest p2 = new PassengerRequest("REGULAR", "John", "MALE", 22, "VEG", 10);

        assertEquals(p1, p2);
        assertEquals(p1.hashCode(), p2.hashCode());
        assertNotNull(p1.toString());
    }

    @Test
    void testValidation() {
        PassengerRequest invalid = new PassengerRequest("", "", "X", -1, "ABC", 0);
        Set<?> violations = validator.validate(invalid);
        assertFalse(violations.isEmpty());
    }
}
