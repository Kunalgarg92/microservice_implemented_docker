package com.flight_service.DTO;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class FlightSearchResponse {
	
	private String airlineName;
    private String flightNumber;
    private LocalDateTime departureTime;
    private LocalDateTime arrivalTime;
    private double oneWayPrice;
    private double roundTripPrice;
    private String message; 
    private LocalDateTime returnDepartureTime;
    private LocalDateTime returnArrivalTime;
    private String returnFlightNumber;
}


