package com.booking_service.service;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.booking_service.Model.Passenger;

class PassengerTest {

    @Test
    void testPassengerGettersSetters() {
        Passenger p = new Passenger();

        p.setId("P1");
        p.setName("John");
        p.setGender("MALE");
        p.setAge(30);
        p.setMeal("VEG");
        p.setSeatNumber(12);
        p.setBookingId("B1");
        p.setFareCategory("REGULAR");
        p.setFareApplied(1500.0);
        p.setFareMessage("OK");

        assertEquals("P1", p.getId());
        assertEquals("John", p.getName());
        assertEquals("MALE", p.getGender());
        assertEquals(30, p.getAge());
        assertEquals("VEG", p.getMeal());
        assertEquals(12, p.getSeatNumber());
        assertEquals("B1", p.getBookingId());
        assertEquals("REGULAR", p.getFareCategory());
        assertEquals(1500.0, p.getFareApplied());
        assertEquals("OK", p.getFareMessage());
    }

    @Test
    void testEqualsAndHashCode() {
        Passenger p1 = new Passenger();
        Passenger p2 = new Passenger();

        p1.setId("A");
        p2.setId("A");

        assertEquals(p1, p2);
        assertEquals(p1.hashCode(), p2.hashCode());
    }

    @Test
    void testToStringNotNull() {
        Passenger p = new Passenger();
        p.setId("P1");
        assertNotNull(p.toString());
    }
}


