package com.flight_service.Controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.flight_service.DTO.FlightInventoryRequest;
import com.flight_service.Model.FlightInventory;
import com.flight_service.Service.FlightInventoryService;

import jakarta.validation.Valid;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/flight/airline")
public class AdminController {

    @Autowired
    FlightInventoryService inventoryService;

    @PostMapping("/inventory")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<String> addInventory(
            @Valid @RequestBody FlightInventoryRequest request) {

        return inventoryService
                .addInventory(request)
                .map(savedFlight -> savedFlight.getId());  
    }

}
