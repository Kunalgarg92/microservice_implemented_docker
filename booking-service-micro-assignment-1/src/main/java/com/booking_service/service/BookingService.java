package com.booking_service.service;


import com.booking_service.DTO.BookingRequest;
import com.booking_service.DTO.BookingResponse;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BookingService {
	Mono<BookingResponse> getBookingByPnr(String pnr);
    Mono<BookingResponse> bookFlight(String flightId, BookingRequest request);
    Flux<BookingResponse> getBookingHistory(String email);
    Mono<Void> cancelBooking(String pnr);
}

