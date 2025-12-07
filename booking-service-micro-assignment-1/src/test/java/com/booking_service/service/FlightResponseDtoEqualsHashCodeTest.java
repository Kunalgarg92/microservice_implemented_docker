package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.FlightResponseDto;

class FlightResponseDtoEqualsHashCodeTest {

    private FlightResponseDto sample() {
        FlightResponseDto d = new FlightResponseDto();
        LocalDateTime now = LocalDateTime.of(2025, 12, 1, 12, 0);
        d.setId("F1");
        d.setAirlineName("Indigo");
        d.setFlightNumber("IN101");
        d.setFromPlace("DEL");
        d.setToPlace("MUM");
        d.setDepartureTime(now);
        d.setArrivalTime(now.plusHours(2));
        d.setTotalSeats(100);
        d.setAvailableSeats(20);
        d.setPrice(5000.0);
        d.setSpecialFare(3000.0);
        d.setFareCategory("STUDENT");
        d.setMessage("OK");
        return d;
    }

    @Test
    void equals_sameReference_and_null_and_differentClass() {
        FlightResponseDto a = sample();
        assertTrue(a.equals(a));
        assertFalse(a.equals(null));
        assertFalse(a.equals("some string"));
    }

    @Test
    void equals_whenAllFieldsEqual_and_hashCode_consistent() {
        FlightResponseDto a = sample();
        FlightResponseDto b = sample();

        assertTrue(a.equals(b));
        assertTrue(b.equals(a));
        assertEquals(a.hashCode(), b.hashCode());

        int h1 = a.hashCode();
        int h2 = a.hashCode();
        assertEquals(h1, h2);
    }

    @Test
    void equals_false_whenFieldDiffers() {
        FlightResponseDto a = sample();
        FlightResponseDto b = sample();
        b.setAirlineName("SpiceJet");       
        assertFalse(a.equals(b));
    }

    @Test
    void equals_handlesNullFields() {
        FlightResponseDto a = sample();
        FlightResponseDto b = sample();

        b.setAirlineName(null);
        b.setMessage(null);

        assertFalse(a.equals(b));

        a.setAirlineName(null);
        a.setMessage(null);
        assertTrue(a.equals(b));
    }

    @Test
    void equals_canEqualFalsePath_usingSubclassOverride() {
        FlightResponseDto base = sample();

        class Sub extends FlightResponseDto {
            @Override
            protected boolean canEqual(Object other) {
                return false; 
            }
        }

        Sub sub = new Sub();
        sub.setId(base.getId());
        sub.setAirlineName(base.getAirlineName());
        sub.setFlightNumber(base.getFlightNumber());
        sub.setFromPlace(base.getFromPlace());
        sub.setToPlace(base.getToPlace());
        sub.setDepartureTime(base.getDepartureTime());
        sub.setArrivalTime(base.getArrivalTime());
        sub.setTotalSeats(base.getTotalSeats());
        sub.setAvailableSeats(base.getAvailableSeats());
        sub.setPrice(base.getPrice());
        sub.setSpecialFare(base.getSpecialFare());
        sub.setFareCategory(base.getFareCategory());
        sub.setMessage(base.getMessage());
        assertFalse(base.equals(sub));
    }
}
