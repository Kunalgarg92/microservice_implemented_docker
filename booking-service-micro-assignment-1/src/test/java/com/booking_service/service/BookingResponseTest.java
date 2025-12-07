package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.BookingResponse;

class BookingResponseTest {

    @Test
    void testGettersSettersAndToString() {
        BookingResponse resp = new BookingResponse();
        Instant now = Instant.now();

        BookingResponse.PassengerInfo info = new BookingResponse.PassengerInfo();
        info.name = "John";
        info.age = 22;
        info.gender = "MALE";
        info.meal = "VEG";
        info.fareCategory = "REGULAR";
        info.fareApplied = 3000.0;
        info.seatNumber = 10;
        info.fareMessage = "OK";

        resp.setPnr("PNR1");
        resp.setEmail("a@b.com");
        resp.setNumberOfSeats(1);
        resp.setTotalPrice(2000);
        resp.setBookingTime(now);
        resp.setPassengers(List.of(info));
        resp.setMessage("OK");

        assertEquals("PNR1", resp.getPnr());
        assertEquals("a@b.com", resp.getEmail());
        assertEquals(1, resp.getNumberOfSeats());
        assertEquals(2000, resp.getTotalPrice());
        assertEquals(now, resp.getBookingTime());
        assertEquals("OK", resp.getMessage());
        assertEquals(1, resp.getPassengers().size());
        assertEquals("John", resp.getPassengers().get(0).name);

        assertNotNull(resp.toString());
    }

    @Test
    void testEqualsAndHashCode() {
        BookingResponse r1 = new BookingResponse();
        BookingResponse r2 = new BookingResponse();

        r1.setPnr("X1");
        r2.setPnr("X1");

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
    }

    @Test
    void testPassengerInfoFields() {
        BookingResponse.PassengerInfo p = new BookingResponse.PassengerInfo();
        p.name = "A";
        p.age = 1;
        p.gender = "MALE";
        p.meal = "VEG";
        p.seatNumber = 5;
        p.fareApplied = 123.0;
        p.fareCategory = "REGULAR";
        p.fareMessage = "MSG";

        assertEquals("A", p.name);
        assertEquals(1, p.age);
        assertEquals("MALE", p.gender);
        assertEquals("VEG", p.meal);
        assertEquals(5, p.seatNumber);
        assertEquals(123.0, p.fareApplied);
        assertEquals("REGULAR", p.fareCategory);
        assertEquals("MSG", p.fareMessage);
    }
}
