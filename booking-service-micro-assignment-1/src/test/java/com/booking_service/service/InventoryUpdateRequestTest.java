package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.booking_service.DTO.InventoryUpdateRequest;

class InventoryUpdateRequestTest {

    @Test
    void testSettersEqualsHashCode() {
        InventoryUpdateRequest r1 = new InventoryUpdateRequest();
        InventoryUpdateRequest r2 = new InventoryUpdateRequest();

        r1.setSeats(5);
        r1.setReason("Booking");
        r1.setBookingId("B1");

        r2.setSeats(5);
        r2.setReason("Booking");
        r2.setBookingId("B1");

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
        assertNotNull(r1.toString());
    }
}
