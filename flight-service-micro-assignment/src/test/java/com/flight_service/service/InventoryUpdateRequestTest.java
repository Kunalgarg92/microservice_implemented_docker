package com.flight_service.service;
import org.junit.jupiter.api.Test;

import com.flight_service.DTO.InventoryUpdateRequest;

import static org.junit.jupiter.api.Assertions.*;

class InventoryUpdateRequestTest {

    @Test
    void testGettersAndSetters() {
        InventoryUpdateRequest req = new InventoryUpdateRequest();

        req.setSeats(5);
        req.setReason("BOOKING");
        req.setBookingId("PNR123");

        assertEquals(5, req.getSeats());
        assertEquals("BOOKING", req.getReason());
        assertEquals("PNR123", req.getBookingId());
    }

    @Test
    void testEqualsAndHashCode() {
        InventoryUpdateRequest req1 = new InventoryUpdateRequest();
        InventoryUpdateRequest req2 = new InventoryUpdateRequest();

        req1.setSeats(5);
        req1.setReason("BOOKING");
        req1.setBookingId("PNR123");

        req2.setSeats(5);
        req2.setReason("BOOKING");
        req2.setBookingId("PNR123");

        assertEquals(req1, req2);
        assertEquals(req1.hashCode(), req2.hashCode());
    }

    @Test
    void testToString() {
        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(3);
        req.setReason("CANCEL");
        req.setBookingId("ABC123");

        String s = req.toString();
        assertTrue(s.contains("seats=3"));
        assertTrue(s.contains("reason=CANCEL"));
        assertTrue(s.contains("bookingId=ABC123"));
    }
}

