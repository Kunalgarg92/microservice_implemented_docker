package com.booking_service.service;


import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.booking_service.Model.Passenger;

class PassengerEqualsHashCodeTest {

    private Passenger makePassenger(String id, String name, int seat) {
        Passenger p = new Passenger();
        p.setId(id);
        p.setName(name);
        p.setGender("MALE");
        p.setAge(30);
        p.setMeal("VEG");
        p.setSeatNumber(seat);
        p.setBookingId("B1");
        p.setFareCategory("REGULAR");
        p.setFareApplied(1000.0);
        p.setFareMessage("OK");
        return p;
    }

    @Test
    void equals_sameRef_null_and_differentType() {
        Passenger p = makePassenger("P1", "John", 1);
        assertTrue(p.equals(p));
        assertFalse(p.equals(null));
        assertFalse(p.equals("x"));
    }

    @Test
    void equals_and_hashCode_for_equal_field_values() {
        Passenger p1 = makePassenger("P1", "John", 1);
        Passenger p2 = makePassenger("P1", "John", 1);
        assertEquals(p1, p2);
        assertEquals(p1.hashCode(), p2.hashCode());
    }

    @Test
    void equals_false_when_field_differs() {
        Passenger p1 = makePassenger("P1", "John", 1);
        Passenger p2 = makePassenger("P1", "John", 2); 
        assertNotEquals(p1, p2);
    }

    @Test
    void toString_notNull_and_stability() {
        Passenger p = makePassenger("P2", "Alice", 5);
        String s = p.toString();
        assertNotNull(s);
        assertEquals(s, p.toString());
    }
}

