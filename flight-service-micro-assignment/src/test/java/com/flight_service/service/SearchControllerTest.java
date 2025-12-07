package com.flight_service.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.flight_service.Controller.SearchController;
import com.flight_service.DTO.FlightSearchRequest;
import com.flight_service.DTO.FlightSearchResponse;
import com.flight_service.Service.FlightInventoryService;

import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class SearchControllerTest {

    @Mock
    private FlightInventoryService inventoryService;

    @InjectMocks
    private SearchController controller;

    @Test
    void search_success() {
        // Arrange - CREATE REAL REQUEST OBJECT
        FlightSearchRequest request = new FlightSearchRequest();
        request.setFromPlace("DELHI");
        request.setToPlace("MUMBAI");
        request.setTravelDate(LocalDate.of(2025, 11, 25));
        request.setTravelTime("09:00");
        request.setTripType("ONE_WAY");

        FlightSearchResponse response = new FlightSearchResponse();
        response.setAirlineName("Indigo");
        response.setFlightNumber("AE101");

        when(inventoryService.searchFlights(any(FlightSearchRequest.class)))
                .thenReturn(Flux.just(response));

        // Act - PASS REAL REQUEST (NOT any())
        StepVerifier.create(controller.search(request))
                .expectNext(response)
                .verifyComplete();

        // Verify service was called with real request
        verify(inventoryService).searchFlights(request);
    }

    @Test
    void search_noResults() {
        // Arrange - CREATE REAL REQUEST OBJECT
        FlightSearchRequest request = new FlightSearchRequest();
        request.setFromPlace("DELHI");
        request.setToPlace("MUMBAI");
        request.setTravelDate(LocalDate.of(2025, 11, 25));
        request.setTripType("ONE_WAY");

        when(inventoryService.searchFlights(any(FlightSearchRequest.class)))
                .thenReturn(Flux.empty());

        // Act - PASS REAL REQUEST
        StepVerifier.create(controller.search(request))
                .expectComplete()
                .verify();

        verify(inventoryService).searchFlights(request);
    }

    @Test
    void search_serviceError() {
        // Arrange - CREATE REAL REQUEST OBJECT
        FlightSearchRequest request = new FlightSearchRequest();
        request.setFromPlace("DELHI");
        request.setToPlace("MUMBAI");
        request.setTravelDate(LocalDate.of(2025, 11, 25));

        when(inventoryService.searchFlights(any(FlightSearchRequest.class)))
                .thenReturn(Flux.error(new RuntimeException("Search failed")));

        // Act - PASS REAL REQUEST
        StepVerifier.create(controller.search(request))
                .expectError(RuntimeException.class)
                .verify();

        verify(inventoryService).searchFlights(request);
    }
}
