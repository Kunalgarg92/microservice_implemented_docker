package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.FlightResponseDto;
import com.booking_service.DTO.InventoryUpdateRequest;
import com.booking_service.Feign.FlightServiceFallback;

class FlightServiceFallbackTest {

    @Test
    void testGetFlightByIdFallback() {
        FlightServiceFallback fallback = new FlightServiceFallback();

        FlightResponseDto dto = fallback.getFlightById("FL123");

        assertNotNull(dto);
        assertEquals("Flight Service is DOWN", dto.getMessage());
        assertEquals(-1, dto.getAvailableSeats());
    }

    @Test
    void testReduceSeatsFallback() {
        FlightServiceFallback fallback = new FlightServiceFallback();

        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(5);
        assertDoesNotThrow(() ->
                fallback.reduceSeats("FL123", req)
        );
    }

    @Test
    void testIncreaseSeatsFallback() {
        FlightServiceFallback fallback = new FlightServiceFallback();

        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(3);
        assertDoesNotThrow(() ->
                fallback.increaseSeats("FL123", req)
        );
    }
}

