package com.flight_service.testutil;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import com.flight_service.Model.FlightInventory;
import com.flight_service.DTO.*;

public class TestData {
    public static FlightInventory flightBasic() {
        FlightInventory f = new FlightInventory();
        f.setId("1");
        f.setAirlineName("Indigo");
        f.setFlightNumber("AE101");
        f.setFromPlace("DELHI"); f.setToPlace("MUMBAI");
        f.setDepartureTime(LocalDateTime.of(2025,11,25,9,0));
        f.setArrivalTime(LocalDateTime.of(2025,11,25,11,0));
        f.setTotalSeats(180); f.setAvailableSeats(10);
        f.setPrice(4500); f.setSpecialFare(3500);
        f.setFareCategory("STUDENT");
        return f;
    }
    

    public static FlightInventoryRequest inventoryRequest() {
        FlightInventoryRequest req = new FlightInventoryRequest();
        req.setAirlineName("Indigo");
        req.setFlightNumber("AE101");
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setDepartureTime(LocalDateTime.of(2025,11,25,9,0));
        req.setArrivalTime(LocalDateTime.of(2025,11,25,11,0));
        req.setTotalSeats(180);
        req.setPrice(4500);
        req.setSpecialFare(3500);
        req.setFareCategory("STUDENT");
        return req;
    }

}
