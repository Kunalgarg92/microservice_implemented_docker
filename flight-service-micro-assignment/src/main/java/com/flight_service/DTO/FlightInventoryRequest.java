package com.flight_service.DTO;
import java.time.LocalDateTime;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class FlightInventoryRequest {
    @NotBlank(message = "Airline name is required")
    @Size(min = 2, max = 50, message = "Airline name must be between 2 and 50 characters")
    private String airlineName;

    @NotBlank(message = "Flight number is required")
    @Pattern(
        regexp = "^[A-Z]{1,2}[0-9]{1,4}$",
        message = "Flight number must follow pattern (e.g., 6E101, AI202)"
    )
    private String flightNumber;

    @NotBlank(message = "Origin airport / city is required")
    @Size(min = 2, max = 50, message = "From place must be between 2 and 50 characters")
    private String fromPlace;

    @NotBlank(message = "Destination airport / city is required")
    @Size(min = 2, max = 50, message = "To place must be between 2 and 50 characters")
    private String toPlace;

    @NotNull(message = "Departure time is required")
    @Future(message = "Departure time must be a future date/time")
    private LocalDateTime departureTime;

    @NotNull(message = "Arrival time is required")
    @Future(message = "Arrival time must be a future date/time")
    private LocalDateTime arrivalTime;

    @Min(value = 1, message = "Total seats must be at least 1")
    private int totalSeats;

    @Positive(message = "Base price must be greater than 0")
    private double price;

    @Positive(message = "Special fare must be greater than 0")
    private double specialFare;

    @NotBlank(message = "Fare category is required")
    @Pattern(
        regexp = "STUDENT|SENIOR|REGULAR|ARMY|CORPORATE",
        message = "Fare category must be one of: STUDENT, SENIOR, REGULAR, ARMY, CORPORATE"
    )
    private String fareCategory;
    
}

