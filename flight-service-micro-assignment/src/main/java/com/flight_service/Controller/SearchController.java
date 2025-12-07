package com.flight_service.Controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import com.flight_service.DTO.FlightSearchRequest;
import com.flight_service.DTO.FlightSearchResponse;
import com.flight_service.Service.FlightInventoryService;

import jakarta.validation.Valid;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/api/flight")
public class SearchController {

    @Autowired
    private FlightInventoryService service;

    @PostMapping("/search")
    @ResponseStatus(HttpStatus.CREATED) 
    public Flux<FlightSearchResponse> search(
            @Valid @RequestBody FlightSearchRequest request) {

        return service.searchFlights(request); 
    }
}