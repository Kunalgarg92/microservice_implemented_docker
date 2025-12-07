package com.flight_service.service;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import com.flight_service.DTO.FlightInventoryRequest;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.time.LocalDateTime;
import java.util.Set;

public class FlightInventoryRequestTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void testGetterSetter() {
        FlightInventoryRequest r = new FlightInventoryRequest();
        LocalDateTime dep = LocalDateTime.now().plusDays(1);
        LocalDateTime arr = LocalDateTime.now().plusDays(1).plusHours(2);
        r.setAirlineName("Indigo");
        r.setFlightNumber("6E101");
        r.setFromPlace("DELHI");
        r.setToPlace("MUMBAI");
        r.setDepartureTime(dep);
        r.setArrivalTime(arr);
        r.setTotalSeats(180);
        r.setPrice(4500);
        r.setSpecialFare(3000);
        r.setFareCategory("STUDENT");
        assertEquals("Indigo", r.getAirlineName());
        assertEquals("6E101", r.getFlightNumber());
        assertEquals("DELHI", r.getFromPlace());
        assertEquals("MUMBAI", r.getToPlace());
        assertEquals(dep, r.getDepartureTime());
        assertEquals(arr, r.getArrivalTime());
        assertEquals(180, r.getTotalSeats());
        assertEquals(4500, r.getPrice());
        assertEquals(3000, r.getSpecialFare());
        assertEquals("STUDENT", r.getFareCategory());
    }

    @Test
    void validationFails_whenInvalid() {
        FlightInventoryRequest r = new FlightInventoryRequest();
        r.setAirlineName("");         
        r.setFlightNumber("123");      
        r.setFromPlace("");           
        r.setToPlace("");              
        r.setDepartureTime(LocalDateTime.now().minusHours(1)); 
        r.setArrivalTime(LocalDateTime.now().minusHours(1));   
        r.setTotalSeats(0);            
        r.setPrice(0);                 
        r.setSpecialFare(0);           
        r.setFareCategory("XYZ");      
        Set<?> violations = validator.validate(r);
        assertFalse(violations.isEmpty());
    }

    @Test
    void validationPasses_whenValid() {
        FlightInventoryRequest r = new FlightInventoryRequest();
        r.setAirlineName("Indigo");
        r.setFlightNumber("AE101");
        r.setFromPlace("DELHI");
        r.setToPlace("MUMBAI");
        r.setDepartureTime(LocalDateTime.now().plusDays(2));
        r.setArrivalTime(LocalDateTime.now().plusDays(2).plusHours(2));
        r.setTotalSeats(180);
        r.setPrice(4500);
        r.setSpecialFare(3500);
        r.setFareCategory("STUDENT");
        Set<?> violations = validator.validate(r);
        assertTrue(violations.isEmpty());
    }
}

