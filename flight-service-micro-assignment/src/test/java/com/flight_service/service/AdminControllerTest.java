package com.flight_service.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.flight_service.Controller.AdminController;
import com.flight_service.DTO.FlightInventoryRequest;
import com.flight_service.Model.FlightInventory;
import com.flight_service.Service.FlightInventoryService;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class AdminControllerTest {

    @Mock
    private FlightInventoryService inventoryService;

    @InjectMocks
    private AdminController adminController;

    @Test
    void addInventory_success() {

        FlightInventoryRequest request = new FlightInventoryRequest();
        request.setAirlineName("Indigo");
        request.setFlightNumber("AE123");
        request.setFromPlace("DELHI");
        request.setToPlace("MUMBAI");
        request.setDepartureTime(LocalDateTime.parse("2025-12-01T10:00:00"));
        request.setArrivalTime(LocalDateTime.parse("2025-12-01T12:00:00"));
        request.setTotalSeats(180);
        request.setPrice(4500.0);
        request.setSpecialFare(3500.0);
        request.setFareCategory("STUDENT");

        FlightInventory saved = new FlightInventory();
        saved.setAirlineName("Indigo");
        saved.setFlightNumber("AE123");
        saved.setId("FL123");  

        when(inventoryService.addInventory(any(FlightInventoryRequest.class)))
                .thenReturn(Mono.just(saved));

        Mono<String> result = adminController.addInventory(request);

        StepVerifier.create(result)
                .expectNext("FL123")    
                .verifyComplete();
    }

}
