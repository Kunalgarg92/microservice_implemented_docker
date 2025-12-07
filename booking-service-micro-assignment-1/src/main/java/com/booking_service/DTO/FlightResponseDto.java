package com.booking_service.DTO;
import lombok.Data;
import java.time.LocalDateTime;
@Data
public class FlightResponseDto {
    private String id;               
    private String airlineName;
    private String flightNumber;
    private String fromPlace;
    private String toPlace;
    private LocalDateTime departureTime;
    private LocalDateTime arrivalTime;
    private int totalSeats;
    private int availableSeats;
    private double price;
    private double specialFare;
    private String fareCategory;   
    private String message;
}


