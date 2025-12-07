package com.booking_service.DTO;
import java.time.Instant;
import java.util.List;

import lombok.Data;

@Data
public class BookingResponse {
	private String pnr;
    private String email;
    private int numberOfSeats;
    private double totalPrice;
    private Instant bookingTime;
    private String message;
    private List<PassengerInfo> passengers;

    public static class PassengerInfo {
        public String name;
        public int seatNumber;
        public String gender;
        public int age;
        public String meal;
        public String fareCategory;
        public double fareApplied;
        public String fareMessage;
    }
}

