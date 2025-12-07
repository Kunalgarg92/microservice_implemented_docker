package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.BookingResponse;

class BookingResponseEqualsHashCodeTest {

    private BookingResponse sample() {
        BookingResponse r = new BookingResponse();
        BookingResponse.PassengerInfo p = new BookingResponse.PassengerInfo();
        p.name = "John";
        p.age = 30;
        p.gender = "MALE";
        p.seatNumber = 5;
        p.meal = "VEG";
        p.fareCategory = "REGULAR";
        p.fareApplied = 1200.0;
        p.fareMessage = "OK";

        r.setPnr("PNR1");
        r.setEmail("a@b.com");
        r.setNumberOfSeats(1);
        r.setTotalPrice(1200.0);
        r.setBookingTime(Instant.parse("2025-12-01T08:00:00Z"));
        r.setMessage("Ticket retrieved");
        r.setPassengers(List.of(p));
        return r;
    }

    @Test
    void equals_sameRef_null_and_differentType() {
        BookingResponse a = sample();
        assertTrue(a.equals(a));
        assertFalse(a.equals(null));
        assertFalse(a.equals("nope"));
    }

    @Test
    void equals_allFieldsEqual_and_hashCode() {
        BookingResponse a = sample();

        BookingResponse b = new BookingResponse();
        b.setPnr(a.getPnr());
        b.setEmail(a.getEmail());
        b.setNumberOfSeats(a.getNumberOfSeats());
        b.setTotalPrice(a.getTotalPrice());
        b.setBookingTime(a.getBookingTime()); 
        b.setMessage(a.getMessage());
        b.setPassengers(a.getPassengers());  
        assertTrue(a.equals(b), "expected a.equals(b) to be true when fields (and passenger list ref) match");
        assertTrue(b.equals(a));
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void equals_whenFieldDiffers() {
        BookingResponse a = sample();
        BookingResponse b = sample();
        b.setEmail("other@example.com");
        assertFalse(a.equals(b));
    }

    @Test
    void equals_handlesNullPassengersAndMessage() {
        BookingResponse a = sample();
        BookingResponse b = sample();

        b.setPassengers(null);
        b.setMessage(null);

        assertFalse(a.equals(b));

        a.setPassengers(null);
        a.setMessage(null);
        assertTrue(a.equals(b));
    }

    @Test
    void equals_canEqualFalsePath_withSubclass() {
        BookingResponse base = sample();

        class Sub extends BookingResponse {
            @Override
            protected boolean canEqual(Object other) {
                return false;
            }
        }

        Sub sub = new Sub();
        sub.setPnr(base.getPnr());
        sub.setEmail(base.getEmail());
        sub.setNumberOfSeats(base.getNumberOfSeats());
        sub.setTotalPrice(base.getTotalPrice());
        sub.setBookingTime(base.getBookingTime());
        sub.setMessage(base.getMessage());
        sub.setPassengers(base.getPassengers());

        assertFalse(base.equals(sub));
    }
}
