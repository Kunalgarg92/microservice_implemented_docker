package com.booking_service.event;

import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
public class BookingEvent {

    private String pnr;
    private String email;
    private int numberOfSeats;
    private double totalPrice;
    private Instant bookingTime;
    private String message;
    private List<PassengerInfo> passengers;

    @Data
    public static class PassengerInfo {
        private String name;
        private int seatNumber;
        private String gender;
        private int age;
        private String meal;
        private String fareCategory;
        private double fareApplied;
        private String fareMessage;
    }
}
