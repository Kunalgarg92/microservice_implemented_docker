package com.booking_service.service.implementation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.booking_service.event.BookingEvent;
import com.booking_service.DTO.BookingRequest;
import com.booking_service.DTO.BookingResponse;
import com.booking_service.DTO.FlightResponseDto;
import com.booking_service.DTO.InventoryUpdateRequest;
import com.booking_service.DTO.PassengerRequest;
import com.booking_service.Feign.FlightServiceClient;
import com.booking_service.Model.BookingStatus;
import com.booking_service.Model.BookingTicket;
import com.booking_service.Model.Passenger;
import com.booking_service.exception.ResourceNotFoundException;
import com.booking_service.kafka.BookingEventProducer;
import com.booking_service.repository.BookingRepository;
import com.booking_service.repository.PassengerRepository;
import com.booking_service.service.BookingService;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class BookingServiceImplementation implements BookingService {

    @Autowired
    private BookingRepository bookingRepo;

    @Autowired
    private PassengerRepository passengerRepo;

    @Autowired
    private FlightServiceClient flightClient;

    @Autowired
    private BookingEventProducer bookingEventProducer;

    
    private static final Random RNG = new Random();

    @Override
    public Mono<BookingResponse> bookFlight(String flightId, BookingRequest request) {

        int seatsRequested = request.getNumberOfSeats();

        if (seatsRequested != request.getPassengers().size()) {
            return Mono.error(new IllegalArgumentException(
                    "numberOfSeats must equal number of passengers"));
        }

        List<Integer> seatNumbers = request.getPassengers()
                .stream()
                .map(PassengerRequest::getSeatNumber)
                .collect(Collectors.toList());

        if (new HashSet<>(seatNumbers).size() != seatNumbers.size()) {
            return Mono.error(new IllegalArgumentException("Duplicate seat numbers in request"));
        }

        return Mono.fromCallable(() -> flightClient.getFlightById(flightId))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(flight -> {

                    if (flight.getAvailableSeats() < seatsRequested)
                        return Mono.error(new IllegalArgumentException("Not enough seats available"));

                    for (Integer s : seatNumbers) {
                        if (s < 1 || s > flight.getTotalSeats()) {
                            return Mono.error(new IllegalArgumentException(
                                    "Seat number " + s + " is invalid for this flight"));
                        }
                    }

                    return generatePnr().flatMap(pnr -> {

                        InventoryUpdateRequest updateReq = new InventoryUpdateRequest();
                        updateReq.setSeats(seatsRequested);
                        updateReq.setReason("BOOKING");
                        updateReq.setBookingId(pnr);

                        
                        return Mono.fromRunnable(() ->
                                flightClient.reduceSeats(flightId, updateReq)
                        ).subscribeOn(Schedulers.boundedElastic())
                                .then(saveBookingAndPassengers(request, flight, flightId, pnr))
                                .onErrorResume(ex ->
                                        Mono.error(new RuntimeException("Seat reservation failed: " + ex.getMessage()))
                                );
                    });
                });
    }

    private Mono<BookingResponse> saveBookingAndPassengers(
            BookingRequest request,
            FlightResponseDto flight,
            String flightId,
            String pnr) {

        BookingTicket booking = new BookingTicket();
        booking.setPnr(pnr);
        booking.setEmail(request.getEmail());
        booking.setFlightId(flightId);
        booking.setBookingTime(Instant.now());
        booking.setNumberOfSeats(request.getNumberOfSeats());
        booking.setStatus(BookingStatus.BOOKED.name());
        booking.setCancelled(false);

        List<Passenger> passengers = new ArrayList<>();
        double totalPrice = 0;

        for (PassengerRequest pr : request.getPassengers()) {
            Passenger p = new Passenger();
            p.setName(pr.getName());
            p.setAge(pr.getAge());
            p.setGender(pr.getGender());
            p.setMeal(pr.getMeal());
            p.setSeatNumber(pr.getSeatNumber());

            p.setFareApplied(flight.getPrice());
            totalPrice += flight.getPrice();

            passengers.add(p);
        }

        booking.setTotalPrice(totalPrice);

        return bookingRepo.save(booking)
                .flatMap(savedBooking -> {
                    passengers.forEach(px -> px.setBookingId(savedBooking.getId()));

                    return passengerRepo.saveAll(passengers)
                            .collectList()
                            .map(savedPassengers -> {
                                BookingResponse response =
                                        buildBookingResponse(savedBooking, savedPassengers, "Booking successful");
                                BookingEvent event = convertToEvent(response);
                                bookingEventProducer.publishBookingConfirmed(event);
                                return response;
                            });
                });
    }

    @Override
    public Mono<BookingResponse> getBookingByPnr(String pnr) {
        return bookingRepo.findByPnr(pnr)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("PNR not found")))
                .flatMap(booking ->
                        passengerRepo.findByBookingId(booking.getId())
                                .collectList()
                                .map(passengers ->
                                        buildBookingResponse(booking, passengers, "Ticket retrieved"))
                );
    }
    @Override
    public Flux<BookingResponse> getBookingHistory(String email) {
        return bookingRepo.findByEmailOrderByBookingTimeDesc(email)
                .flatMap(booking ->
                        passengerRepo.findByBookingId(booking.getId())
                                .collectList()
                                .map(passengers ->
                                        buildBookingResponse(booking, passengers, "History item"))
                );
    }
    @Override
    public Mono<Void> cancelBooking(String pnr) {

        return bookingRepo.findByPnr(pnr)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("PNR not found")))
                .flatMap(booking -> {

                    InventoryUpdateRequest req = new InventoryUpdateRequest();
                    req.setSeats(booking.getNumberOfSeats());
                    req.setReason("CANCEL");
                    req.setBookingId(booking.getPnr());

                    return Mono.fromRunnable(() ->
                            flightClient.increaseSeats(booking.getFlightId(), req)
                    ).subscribeOn(Schedulers.boundedElastic())
                            .then(bookingRepo.delete(booking));
                });
    }

    private Mono<String> generatePnr() {
        return Mono.just(randomAlphaNumeric(6));
    }

    private String randomAlphaNumeric(int length) {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(RNG.nextInt(chars.length())));
        }
        return sb.toString();
    }
    
    private BookingEvent convertToEvent(BookingResponse response) {

        BookingEvent event = new BookingEvent();
        event.setPnr(response.getPnr());
        event.setEmail(response.getEmail());
        event.setNumberOfSeats(response.getNumberOfSeats());
        event.setTotalPrice(response.getTotalPrice());
        event.setBookingTime(response.getBookingTime());
        event.setMessage(response.getMessage());

        event.setPassengers(response.getPassengers().stream().map(p -> {
            BookingEvent.PassengerInfo info = new BookingEvent.PassengerInfo();
            info.setName(p.name);
            info.setSeatNumber(p.seatNumber);
            info.setGender(p.gender);
            info.setAge(p.age);
            info.setMeal(p.meal);
            info.setFareCategory(p.fareCategory);
            info.setFareApplied(p.fareApplied);
            info.setFareMessage(p.fareMessage);
            return info;
        }).toList());

        return event;
    }


    // BUILD RESPONSE
    private BookingResponse buildBookingResponse(BookingTicket booking,
                                                 List<Passenger> passengers,
                                                 String message) {

        BookingResponse resp = new BookingResponse();
        resp.setPnr(booking.getPnr());
        resp.setEmail(booking.getEmail());
        resp.setNumberOfSeats(booking.getNumberOfSeats());
        resp.setTotalPrice(booking.getTotalPrice());
        resp.setBookingTime(booking.getBookingTime());
        resp.setMessage(message);

        resp.setPassengers(
                passengers.stream().map(px -> {
                    BookingResponse.PassengerInfo info = new BookingResponse.PassengerInfo();
                    info.name = px.getName();
                    info.age = px.getAge();
                    info.gender = px.getGender();
                    info.meal = px.getMeal();
                    info.seatNumber = px.getSeatNumber();
                    info.fareCategory = px.getFareCategory();
                    info.fareApplied = px.getFareApplied();
                    info.fareMessage = px.getFareMessage();
                    return info;
                }).collect(Collectors.toList())
        );

        return resp;
    }
}
