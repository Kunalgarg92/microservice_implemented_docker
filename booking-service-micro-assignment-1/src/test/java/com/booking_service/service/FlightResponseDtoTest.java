package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.FlightResponseDto;

class FlightResponseDtoTest {

    @Test
    void testGettersSettersAndToString() {
        FlightResponseDto dto = new FlightResponseDto();
        LocalDateTime now = LocalDateTime.now();

        dto.setId("F1");
        dto.setAirlineName("Indigo");
        dto.setFlightNumber("IN101");
        dto.setFromPlace("DEL");
        dto.setToPlace("MUM");
        dto.setDepartureTime(now);
        dto.setArrivalTime(now.plusHours(1));
        dto.setTotalSeats(100);
        dto.setAvailableSeats(20);
        dto.setPrice(5000);
        dto.setSpecialFare(3000);
        dto.setFareCategory("STUDENT");
        dto.setMessage("OK");

        assertEquals("F1", dto.getId());
        assertEquals("Indigo", dto.getAirlineName());
        assertEquals("IN101", dto.getFlightNumber());
        assertEquals("DEL", dto.getFromPlace());
        assertEquals("MUM", dto.getToPlace());
        assertEquals(100, dto.getTotalSeats());
        assertEquals(20, dto.getAvailableSeats());
        assertEquals(5000, dto.getPrice());
        assertEquals(3000, dto.getSpecialFare());
        assertEquals("STUDENT", dto.getFareCategory());
        assertEquals("OK", dto.getMessage());

        assertNotNull(dto.toString());
    }

    @Test
    void testEqualsAndHashCode() {
        FlightResponseDto d1 = new FlightResponseDto();
        FlightResponseDto d2 = new FlightResponseDto();

        d1.setId("F1");
        d2.setId("F1");

        assertEquals(d1, d2);
        assertEquals(d1.hashCode(), d2.hashCode());
    }
}
