package com.flight_service.Controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.flight_service.DTO.InventoryUpdateRequest;
import com.flight_service.Model.FlightInventory;
import com.flight_service.Service.FlightInventoryService;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/flight/internal")
public class InternalFlightController {

    @Autowired
    private FlightInventoryService inventoryService;
    
    @GetMapping("/{flightId}")
    public Mono<ResponseEntity<FlightInventory>> getFlightById(@PathVariable String flightId) {
        return inventoryService.getFlightById(flightId)
                .map(ResponseEntity::ok)
                .switchIfEmpty(Mono.just(ResponseEntity.notFound().build()));
    }

    @PostMapping("/{flightId}/inventory/reduce")
    public ResponseEntity<String> reduceInventory(
            @PathVariable String flightId,
            @RequestBody InventoryUpdateRequest request) {

        inventoryService.reduceSeats(flightId, request);
        return ResponseEntity.ok("Seats reduced successfully");
    }

    @PostMapping("/{flightId}/inventory/increase")
    public ResponseEntity<String> increaseInventory(
            @PathVariable String flightId,
            @RequestBody InventoryUpdateRequest request) {
    	
        inventoryService.increaseSeats(flightId, request);
        return ResponseEntity.ok("Seats increased successfully");
    }
}
