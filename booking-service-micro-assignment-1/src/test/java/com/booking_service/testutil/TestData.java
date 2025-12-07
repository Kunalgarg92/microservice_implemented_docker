package com.booking_service.testutil;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import com.booking_service.DTO.BookingRequest;
import com.booking_service.DTO.PassengerRequest;

public class TestData {
    public static PassengerRequest passenger(String category, String name, int age, int seat) {
        PassengerRequest p = new PassengerRequest();
        p.setFareCategory(category);
        p.setName(name);
        p.setAge(age);
        p.setGender("MALE");
        p.setMeal("VEG");
        p.setSeatNumber(seat);
        return p;
    }

    public static BookingRequest bookingReq(String email, int seats, List<PassengerRequest> passengers) {
        BookingRequest r = new BookingRequest();
        r.setEmail(email);
        r.setNumberOfSeats(seats);
        r.setPassengers(passengers);
        return r;
    }
}
