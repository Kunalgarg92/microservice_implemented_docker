package com.booking_service.Model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import lombok.Data;

@Data
@Document(collection = "booking_ticket")
public class BookingTicket {

    @Id
    private String id;  

    @Field("pnr")
    private String pnr;

    @Field("email")
    private String email;

    @Field("flight_id")
    private String flightId;

    @Field("booking_time")
    private Instant bookingTime;

    @Field("number_of_seats")
    private int numberOfSeats;

    @Field("total_price")
    private double totalPrice;

    @Field("status")
    private String status;

    @Field("cancelled")
    private boolean cancelled = false;

    @Field("passengers")
    private List<Passenger> passengers = new ArrayList<>();
}
