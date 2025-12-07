package com.booking_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.booking_service.DTO.BookingRequest;
import com.booking_service.DTO.BookingResponse;
import com.booking_service.DTO.FlightResponseDto;
import com.booking_service.DTO.PassengerRequest;
import com.booking_service.Model.BookingTicket;
import com.booking_service.Model.Passenger;
import com.booking_service.exception.ResourceNotFoundException;
import com.booking_service.repository.BookingRepository;
import com.booking_service.repository.PassengerRepository;
import com.booking_service.Feign.FlightServiceClient;
import com.booking_service.service.implementation.BookingServiceImplementation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class BookingServiceImplementationTest {

    @Mock
    BookingRepository bookingRepo;

    @Mock
    PassengerRepository passengerRepo;

    @Mock
    FlightServiceClient flightClient;

    @InjectMocks
    BookingServiceImplementation service;

    private FlightResponseDto flightDto(int totalSeats, int availableSeats, double price) {
        FlightResponseDto f = new FlightResponseDto();
        f.setTotalSeats(totalSeats);
        f.setAvailableSeats(availableSeats);
        f.setPrice(price);
        return f;
    }

    @Test
    void bookFlight_fails_when_numberOfSeats_mismatch() {
        BookingRequest req = new BookingRequest();
        req.setEmail("a@b.com");
        req.setNumberOfSeats(2);
        req.setPassengers(List.of(new PassengerRequest("REGULAR","A","MALE",20,"VEG",1)));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.bookFlight("FL1", req).block());

        assertTrue(ex.getMessage().contains("numberOfSeats must equal number of passengers"));
    }

    @Test
    void bookFlight_fails_when_duplicate_seat_numbers() {
        BookingRequest req = new BookingRequest();
        req.setEmail("a@b.com");
        req.setNumberOfSeats(2);
        req.setPassengers(List.of(
                new PassengerRequest("REGULAR","A","MALE",20,"VEG",5),
                new PassengerRequest("REGULAR","B","FEMALE",21,"VEG",5)
        ));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.bookFlight("FL1", req).block());

        assertTrue(ex.getMessage().contains("Duplicate seat numbers"));
    }

    @Test
    void bookFlight_fails_when_not_enough_seats_available() {
        BookingRequest req = new BookingRequest();
        req.setEmail("a@b.com");
        req.setNumberOfSeats(2);
        req.setPassengers(List.of(
                new PassengerRequest("REGULAR","A","MALE",20,"VEG",1),
                new PassengerRequest("REGULAR","B","FEMALE",21,"VEG",2)
        ));

        when(flightClient.getFlightById("FL1")).thenReturn(flightDto(100, 1, 1000));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.bookFlight("FL1", req).block());

        assertTrue(ex.getMessage().contains("Not enough seats available"));
    }

    @Test
    void bookFlight_fails_when_seat_out_of_range() {
        BookingRequest req = new BookingRequest();
        req.setEmail("a@b.com");
        req.setNumberOfSeats(1);
        req.setPassengers(List.of(new PassengerRequest("REGULAR","A","MALE",20,"VEG",999)));

        when(flightClient.getFlightById("FL1")).thenReturn(flightDto(100, 50, 1500));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.bookFlight("FL1", req).block());

        assertTrue(ex.getMessage().contains("is invalid for this flight"));
    }

    @Test
    void bookFlight_success_saves_booking_and_passengers_and_calls_reduceSeats() {
        BookingRequest req = new BookingRequest();
        req.setEmail("cust@example.com");
        req.setNumberOfSeats(2);
        req.setPassengers(List.of(
                new PassengerRequest("REGULAR","P1","MALE",30,"VEG",1),
                new PassengerRequest("REGULAR","P2","FEMALE",28,"VEG",2)
        ));

        when(flightClient.getFlightById("FL1")).thenReturn(flightDto(100, 10, 2500));

        when(bookingRepo.save(any(BookingTicket.class)))
                .thenAnswer(inv -> {
                    BookingTicket b = inv.getArgument(0);
                    b.setId("BID1");
                    return Mono.just(b);
                });

        when(passengerRepo.saveAll(anyIterable()))
                .thenAnswer(inv -> {
                    List<Passenger> list = new ArrayList<>();
                    inv.<Iterable<Passenger>>getArgument(0).forEach(list::add);
                    return Flux.fromIterable(list);
                });

        BookingResponse resp = service.bookFlight("FL1", req).block();

        assertNotNull(resp);
        assertEquals("cust@example.com", resp.getEmail());
        assertEquals(2, resp.getNumberOfSeats());
        assertEquals("Booking successful", resp.getMessage());
        assertEquals(2, resp.getPassengers().size());

        verify(flightClient, times(1)).reduceSeats(eq("FL1"), any());
        verify(bookingRepo, times(1)).save(any());
    }

    @Test
    void getBookingByPnr_success() {
        BookingTicket b = new BookingTicket();
        b.setId("B1");
        b.setPnr("PNR1");
        b.setEmail("x@y.com");
        b.setNumberOfSeats(1);
        b.setTotalPrice(1000);
        b.setBookingTime(Instant.now());

        Passenger pax = new Passenger();
        pax.setName("A");
        pax.setAge(20);
        pax.setGender("MALE");
        pax.setMeal("VEG");
        pax.setSeatNumber(1);
        pax.setFareApplied(1000);

        when(bookingRepo.findByPnr("PNR1")).thenReturn(Mono.just(b));
        when(passengerRepo.findByBookingId("B1")).thenReturn(Flux.just(pax));

        BookingResponse resp = service.getBookingByPnr("PNR1").block();

        assertNotNull(resp);
        assertEquals("PNR1", resp.getPnr());
        assertEquals("Ticket retrieved", resp.getMessage());
        assertEquals(1, resp.getPassengers().size());
    }

    @Test
    void getBookingByPnr_not_found_throws() {
        when(bookingRepo.findByPnr("NO")).thenReturn(Mono.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> service.getBookingByPnr("NO").block());
    }

    @Test
    void getBookingHistory_returns_mapped_items() {
        BookingTicket b1 = new BookingTicket();
        b1.setId("B1");
        b1.setPnr("P1");
        b1.setEmail("a@b.com");
        b1.setNumberOfSeats(1);
        b1.setTotalPrice(100);

        BookingTicket b2 = new BookingTicket();
        b2.setId("B2");
        b2.setPnr("P2");
        b2.setEmail("a@b.com");
        b2.setNumberOfSeats(2);
        b2.setTotalPrice(200);

        when(bookingRepo.findByEmailOrderByBookingTimeDesc("a@b.com"))
                .thenReturn(Flux.just(b1, b2));

        when(passengerRepo.findByBookingId("B1")).thenReturn(Flux.just(new Passenger()));
        when(passengerRepo.findByBookingId("B2")).thenReturn(Flux.just(new Passenger()));

        List<BookingResponse> list = service.getBookingHistory("a@b.com")
                                            .collectList()
                                            .block();

        assertEquals(2, list.size());
        assertEquals("P1", list.get(0).getPnr());
        assertEquals("P2", list.get(1).getPnr());
    }

    @Test
    void cancelBooking_success_calls_increase_and_deletes_booking() {
        BookingTicket b = new BookingTicket();
        b.setId("B1");
        b.setPnr("PNR123");
        b.setFlightId("FL1");
        b.setNumberOfSeats(2);

        when(bookingRepo.findByPnr("PNR123")).thenReturn(Mono.just(b));
        when(bookingRepo.delete(b)).thenReturn(Mono.empty());

        service.cancelBooking("PNR123").block();

        verify(flightClient, times(1)).increaseSeats(eq("FL1"), any());
        verify(bookingRepo, times(1)).delete(b);
    }

    @Test
    void cancelBooking_not_found_throws() {
        when(bookingRepo.findByPnr("X")).thenReturn(Mono.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> service.cancelBooking("X").block());
    }
}
