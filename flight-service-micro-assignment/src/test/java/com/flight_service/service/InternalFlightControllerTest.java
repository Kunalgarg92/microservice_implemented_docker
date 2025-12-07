package com.flight_service.service;

import com.flight_service.Controller.InternalFlightController;
import com.flight_service.DTO.InventoryUpdateRequest;
import com.flight_service.Model.FlightInventory;
import com.flight_service.Service.FlightInventoryService;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import reactor.core.publisher.Mono;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class InternalFlightControllerTest {

    @Mock
    private FlightInventoryService inventoryService;

    @InjectMocks
    private InternalFlightController controller;

    @Test
    void getFlightById_success() {
        FlightInventory flight = new FlightInventory();
        flight.setId("F1");

        when(inventoryService.getFlightById("F1"))
                .thenReturn(Mono.just(flight));

        ResponseEntity<FlightInventory> response =
                controller.getFlightById("F1").block();

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        assertEquals("F1", response.getBody().getId());
    }

    @Test
    void getFlightById_notFound() {
        when(inventoryService.getFlightById("X"))
                .thenReturn(Mono.empty());

        ResponseEntity<FlightInventory> response =
                controller.getFlightById("X").block();

        assertEquals(404, response.getStatusCode().value());
        assertNull(response.getBody());
    }

    @Test
    void reduceInventory_success() {
        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(2);
        req.setReason("BOOKING");

        ResponseEntity<String> response =
                controller.reduceInventory("F100", req);

        assertEquals(200, response.getStatusCode().value());
        assertEquals("Seats reduced successfully", response.getBody());
    }

    @Test
    void increaseInventory_success() {
        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(3);
        req.setReason("CANCEL");

        ResponseEntity<String> response =
                controller.increaseInventory("F200", req);

        assertEquals(200, response.getStatusCode().value());
        assertEquals("Seats increased successfully", response.getBody());
    }
}
