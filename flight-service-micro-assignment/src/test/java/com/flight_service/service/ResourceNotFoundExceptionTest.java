package com.flight_service.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

import com.flight_service.exception.ResourceNotFoundException;


class ResourceNotFoundExceptionTest {

    @Test
    void storesMessageCorrectly() {
        ResourceNotFoundException ex =  new ResourceNotFoundException("Flight not found");
        assertEquals("Flight not found", ex.getMessage());
    }
}

