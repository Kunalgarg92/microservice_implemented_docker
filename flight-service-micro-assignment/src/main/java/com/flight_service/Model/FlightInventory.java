package com.flight_service.Model;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Document(collection = "flight_inventory")
public class FlightInventory {

    @Id
    private String id;  

    @Field("airline_name")
    @NotBlank(message = "Airline name is required")
    @Size(min = 2, max = 50, message = "Airline name must be between 2 and 50 characters")
    private String airlineName;

    @Field("flight_number")
    @NotBlank(message = "Flight number is required")
    @Pattern(regexp = "^[A-Z0-9]{2,8}$",
             message = "Flight number must be uppercase alphanumeric (2-8 characters)")
    private String flightNumber;

    @Field("from_place")
    @NotBlank(message = "From place is required")
    @Size(min = 2, max = 50, message = "From place must be between 2 and 50 characters")
    private String fromPlace;

    @Field("to_place")
    @NotBlank(message = "To place is required")
    @Size(min = 2, max = 50, message = "To place must be between 2 and 50 characters")
    private String toPlace;

    @Field("departure_time")
    @NotNull(message = "Departure time cannot be null")
    @Future(message = "Departure time must be in the future")
    private LocalDateTime departureTime;

    @Field("arrival_time")
    @NotNull(message = "Arrival time cannot be null")
    @Future(message = "Arrival time must be in the future")
    private LocalDateTime arrivalTime;

    @Field("total_seats")
    @Min(value = 1, message = "Total seats must be at least 1")
    private int totalSeats;

    @Field("available_seats")
    @Min(value = 0, message = "Available seats cannot be negative")
    private int availableSeats;

    @Field("price")
    @Positive(message = "Price must be a positive value")
    private double price;

    @Field("special_fare")
    @Positive(message = "Special fare must be a positive value")
    private double specialFare;

    @Field("fare_category")
    @NotBlank(message = "Fare category is required")
    @Pattern(
        regexp = "STUDENT|SENIOR|REGULAR|ARMY|CORPORATE",
        message = "Fare category must be one of: STUDENT, SENIOR, REGULAR, ARMY, CORPORATE"
    )
    private String fareCategory;
}


