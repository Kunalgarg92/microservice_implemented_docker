package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.BookingRequest;
import com.booking_service.DTO.PassengerRequest;

class BookingRequestTest {

    @Test
    void testSettersEqualsHashCode() {
        BookingRequest r1 = new BookingRequest();
        BookingRequest r2 = new BookingRequest();

        PassengerRequest p = new PassengerRequest("REGULAR", "John", "MALE", 25, "VEG", 10);

        r1.setEmail("a@b.com");
        r1.setNumberOfSeats(1);
        r1.setPassengers(List.of(p));

        r2.setEmail("a@b.com");
        r2.setNumberOfSeats(1);
        r2.setPassengers(List.of(p));

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
        assertNotNull(r1.toString());

        assertEquals("a@b.com", r1.getEmail());
    }
}
