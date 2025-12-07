package com.booking_service.repository;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import com.booking_service.Model.BookingTicket;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface BookingRepository extends ReactiveMongoRepository<BookingTicket, String> {

    Mono<BookingTicket> findByPnr(String pnr);

    Flux<BookingTicket> findByEmailOrderByBookingTimeDesc(String email);
    
    Flux<BookingTicket> findByFlightId(String flightId);

}
