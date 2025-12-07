package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.booking_service.Model.BookingTicket;
import com.booking_service.Model.Passenger;

class BookingTicketEqualsHashCodeTest {

    private BookingTicket makeSample() {
        BookingTicket t = new BookingTicket();
        t.setId("T1");
        t.setPnr("PNR001");
        t.setEmail("test@example.com");
        t.setFlightId("FL101");
        t.setBookingTime(Instant.parse("2025-12-01T08:00:00Z"));
        t.setNumberOfSeats(2);
        t.setTotalPrice(5000.0);
        t.setStatus("CONFIRMED");
        t.setCancelled(false);

        Passenger p1 = new Passenger();
        p1.setId("P1"); p1.setName("John"); p1.setSeatNumber(1);

        Passenger p2 = new Passenger();
        p2.setId("P2"); p2.setName("Alice"); p2.setSeatNumber(2);

        List<Passenger> list = new ArrayList<>();
        list.add(p1);
        list.add(p2);
        t.setPassengers(list);
        return t;
    }

    @Test
    void equals_sameRef_null_and_differentClass() {
        BookingTicket a = makeSample();
        assertTrue(a.equals(a));
        assertFalse(a.equals(null));
        assertFalse(a.equals("not a booking"));
    }

    @Test
    void equals_allFieldsEqual_and_hashCode_consistent() {
        BookingTicket a = makeSample();
        BookingTicket b = new BookingTicket();
        b.setId(a.getId());
        b.setPnr(a.getPnr());
        b.setEmail(a.getEmail());
        b.setFlightId(a.getFlightId());
        b.setBookingTime(a.getBookingTime());
        b.setNumberOfSeats(a.getNumberOfSeats());
        b.setTotalPrice(a.getTotalPrice());
        b.setStatus(a.getStatus());
        b.setCancelled(a.isCancelled());

        List<Passenger> blist = new ArrayList<>();
        for (Passenger p : a.getPassengers()) {
            Passenger np = new Passenger();
            np.setId(p.getId());
            np.setName(p.getName());
            np.setSeatNumber(p.getSeatNumber());
            np.setAge(p.getAge());
            np.setGender(p.getGender());
            np.setMeal(p.getMeal());
            np.setBookingId(p.getBookingId());
            np.setFareCategory(p.getFareCategory());
            np.setFareApplied(p.getFareApplied());
            np.setFareMessage(p.getFareMessage());
            blist.add(np);
        }
        b.setPassengers(blist);

        assertTrue(a.equals(b));
        assertTrue(b.equals(a));
        assertEquals(a.hashCode(), b.hashCode());

        int h1 = a.hashCode();
        int h2 = a.hashCode();
        assertEquals(h1, h2);
    }

    @Test
    void equals_false_whenFieldDiffers() {
        BookingTicket a = makeSample();
        BookingTicket b = makeSample();
        b.setEmail("other@example.com");
        assertFalse(a.equals(b));
    }

    @Test
    void equals_handlesNullPassengersAndMessage() {
        BookingTicket a = makeSample();
        BookingTicket b = makeSample();

        b.setPassengers(null);
        assertFalse(a.equals(b));

        a.setPassengers(null);
        assertTrue(a.equals(b));
    }

    @Test
    void equals_canEqualFalsePath_withSubclass() {
        BookingTicket base = makeSample();

        class Sub extends BookingTicket {
            @Override
            protected boolean canEqual(Object other) {
                return false;
            }
        }

        Sub sub = new Sub();
        sub.setId(base.getId());
        sub.setPnr(base.getPnr());
        sub.setEmail(base.getEmail());
        sub.setFlightId(base.getFlightId());
        sub.setBookingTime(base.getBookingTime());
        sub.setNumberOfSeats(base.getNumberOfSeats());
        sub.setTotalPrice(base.getTotalPrice());
        sub.setStatus(base.getStatus());
        sub.setCancelled(base.isCancelled());
        sub.setPassengers(base.getPassengers());

        assertFalse(base.equals(sub));
    }

    @Test
    void toString_and_defaults() {
        BookingTicket t = new BookingTicket();
        assertNotNull(t.toString());
        assertFalse(t.isCancelled());
        assertNotNull(t.getPassengers());
    }
}

