package com.flight_service.Service;

import com.flight_service.DTO.FlightInventoryRequest;
import com.flight_service.DTO.FlightSearchRequest;
import com.flight_service.DTO.FlightSearchResponse;
import com.flight_service.DTO.InventoryUpdateRequest;
import com.flight_service.Model.FlightInventory;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface FlightInventoryService {
    Mono<FlightInventory> addInventory(FlightInventoryRequest request);
    Flux<FlightSearchResponse> searchFlights(FlightSearchRequest request);
    Mono<FlightInventory> getFlightById(String flightId);
    Mono<Void> reduceSeats(String flightId, InventoryUpdateRequest request);
    Mono<Void> increaseSeats(String flightId, InventoryUpdateRequest request);
}

