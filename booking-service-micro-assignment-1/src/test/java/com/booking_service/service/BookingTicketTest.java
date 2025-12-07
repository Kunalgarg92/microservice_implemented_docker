package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.booking_service.Model.BookingTicket;
import com.booking_service.Model.Passenger;

class BookingTicketTest {

    @Test
    void testBookingTicketGettersSetters() {
        BookingTicket ticket = new BookingTicket();

        Instant now = Instant.now();

        Passenger p1 = new Passenger();
        p1.setName("John");

        Passenger p2 = new Passenger();
        p2.setName("Alice");

        List<Passenger> list = new ArrayList<>();
        list.add(p1);
        list.add(p2);

        ticket.setId("T1");
        ticket.setPnr("PNR001");
        ticket.setEmail("test@example.com");
        ticket.setFlightId("FL101");
        ticket.setBookingTime(now);
        ticket.setNumberOfSeats(2);
        ticket.setTotalPrice(5000.0);
        ticket.setStatus("CONFIRMED");
        ticket.setCancelled(true);
        ticket.setPassengers(list);

        assertEquals("T1", ticket.getId());
        assertEquals("PNR001", ticket.getPnr());
        assertEquals("test@example.com", ticket.getEmail());
        assertEquals("FL101", ticket.getFlightId());
        assertEquals(now, ticket.getBookingTime());
        assertEquals(2, ticket.getNumberOfSeats());
        assertEquals(5000.0, ticket.getTotalPrice());
        assertEquals("CONFIRMED", ticket.getStatus());
        assertTrue(ticket.isCancelled());
        assertEquals(2, ticket.getPassengers().size());
        assertEquals("John", ticket.getPassengers().get(0).getName());
        assertEquals("Alice", ticket.getPassengers().get(1).getName());
    }

    @Test
    void testDefaultCancelledFalse() {
        BookingTicket ticket = new BookingTicket();
        assertFalse(ticket.isCancelled());
    }

    @Test
    void testDefaultPassengerListNotNull() {
        BookingTicket ticket = new BookingTicket();
        assertNotNull(ticket.getPassengers());
        assertTrue(ticket.getPassengers().isEmpty());
        ticket.getPassengers().add(new Passenger());
        assertEquals(1, ticket.getPassengers().size());
    }

    @Test
    void testEqualsAndHashCode() {
        BookingTicket t1 = new BookingTicket();
        BookingTicket t2 = new BookingTicket();

        t1.setId("X1");
        t2.setId("X1");

        assertEquals(t1, t2);
        assertEquals(t1.hashCode(), t2.hashCode());
    }

    @Test
    void testToStringNotNull() {
        BookingTicket t = new BookingTicket();
        t.setId("T100");
        assertNotNull(t.toString());
    }
}
