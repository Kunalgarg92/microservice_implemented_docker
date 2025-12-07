package com.booking_service.Feign;

import org.springframework.stereotype.Component;
import com.booking_service.DTO.FlightResponseDto;
import com.booking_service.DTO.InventoryUpdateRequest;

@Component
public class FlightServiceFallback implements FlightServiceClient {

    @Override
    public FlightResponseDto getFlightById(String flightId) {
    	System.out.println("DEBUG: FlightServiceFallback.getFlightById invoked for " + flightId);
        FlightResponseDto dto = new FlightResponseDto();
        dto.setMessage("Flight Service is DOWN");
        dto.setAvailableSeats(-1);  
        return dto;
    }

    @Override
    public void reduceSeats(String id, InventoryUpdateRequest request) {
        System.out.println("Flight service DOWN. reduceSeats() fallback.");
    }

    @Override
    public void increaseSeats(String id, InventoryUpdateRequest request) {
        System.out.println("Flight service DOWN. increaseSeats() fallback.");
    }
}

