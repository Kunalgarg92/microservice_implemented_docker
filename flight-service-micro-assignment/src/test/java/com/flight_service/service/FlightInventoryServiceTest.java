package com.flight_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.flight_service.DTO.FlightInventoryRequest;
import com.flight_service.DTO.FlightSearchRequest;
import com.flight_service.DTO.FlightSearchResponse;
import com.flight_service.DTO.InventoryUpdateRequest;
import com.flight_service.Model.FlightInventory;
import com.flight_service.Service.implementation.FlightInventoryServiceImplementation;
import com.flight_service.repository.FlightInventoryRepository;
import com.flight_service.testutil.TestData;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class FlightInventoryServiceTest {

    @Mock
    private FlightInventoryRepository repo;

    @InjectMocks
    private FlightInventoryServiceImplementation service;

    // -----------------------------
    // Your existing tests
    // -----------------------------

    @Test
    void testSearchOneWayFlightSuccess() {
        FlightSearchRequest req = new FlightSearchRequest();
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setTravelDate(LocalDate.of(2025, 11, 25));
        req.setTravelTime("");
        req.setTripType("ONE_WAY");

        FlightInventory f = new FlightInventory();
        f.setAirlineName("Indigo");
        f.setFlightNumber("AE101");
        f.setPrice(4500);

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("DELHI"), eq("MUMBAI"),
                any(LocalDateTime.class), any(LocalDateTime.class)
        )).thenReturn(Flux.just(f));

        List<FlightSearchResponse> result =
                service.searchFlights(req).collectList().block();

        assertEquals(1, result.size());
        assertEquals("Indigo", result.get(0).getAirlineName());
    }

    @Test
    void testRoundTripWhenReturnFlightNotAvailable() {
        FlightSearchRequest req = new FlightSearchRequest();
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setTripType("ROUND_TRIP");
        req.setTravelDate(LocalDate.of(2025, 11, 25));
        req.setReturnDate(LocalDate.of(2025, 11, 28));

        FlightInventory f1 = new FlightInventory();
        f1.setAirlineName("Indigo");
        f1.setFlightNumber("AE101");
        f1.setPrice(4500);

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("DELHI"), eq("MUMBAI"), any(), any()
        )).thenReturn(Flux.just(f1));

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("MUMBAI"), eq("DELHI"), any(), any()
        )).thenReturn(Flux.empty());

        List<FlightSearchResponse> result =
                service.searchFlights(req).collectList().block();

        assertEquals("Only onward flight available. Return flight not found.",
                result.get(0).getMessage());
    }

    @Test
    void oneWay_noTime_searchWholeDay() {
        FlightSearchRequest req = new FlightSearchRequest();
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setTravelDate(LocalDate.of(2025, 11, 25));
        req.setTravelTime("");
        req.setTripType("ONE_WAY");

        FlightInventory f = TestData.flightBasic();

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("DELHI"), eq("MUMBAI"), any(), any()
        )).thenReturn(Flux.just(f));

        var got = service.searchFlights(req).collectList().block();

        assertEquals(1, got.size());
        assertEquals("AE101", got.get(0).getFlightNumber());
    }

    @Test
    void oneWay_withTime_searchWindow() {
        FlightSearchRequest req = new FlightSearchRequest();
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setTravelDate(LocalDate.of(2025, 11, 25));
        req.setTravelTime("09:00");
        req.setTripType("ONE_WAY");

        FlightInventory f = TestData.flightBasic();

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("DELHI"), eq("MUMBAI"), any(), any()
        )).thenReturn(Flux.just(f));

        var got = service.searchFlights(req).collectList().block();
        assertFalse(got.isEmpty());
    }

    @Test
    void roundTrip_returnNotFound_setsMessage() {
        FlightSearchRequest req = new FlightSearchRequest();
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setTripType("ROUND_TRIP");
        req.setTravelDate(LocalDate.of(2025, 11, 25));
        req.setReturnDate(LocalDate.of(2025, 11, 28));

        FlightInventory f = TestData.flightBasic();

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("DELHI"), eq("MUMBAI"), any(), any()
        )).thenReturn(Flux.just(f));

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("MUMBAI"), eq("DELHI"), any(), any()
        )).thenReturn(Flux.empty());

        var out = service.searchFlights(req).collectList().block();
        assertEquals("Only onward flight available. Return flight not found.",
                out.get(0).getMessage());
    }

    @Test
    void roundTrip_withReturn_populatesReturnDetails() {
        FlightInventory f1 = TestData.flightBasic();

        FlightInventory r1 = TestData.flightBasic();
        r1.setFromPlace("MUMBAI");
        r1.setToPlace("DELHI");
        r1.setFlightNumber("AE102");

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("DELHI"), eq("MUMBAI"), any(), any()
        )).thenReturn(Flux.just(f1));

        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
                eq("MUMBAI"), eq("DELHI"), any(), any()
        )).thenReturn(Flux.just(r1));

        FlightSearchRequest req = new FlightSearchRequest();
        req.setFromPlace("DELHI");
        req.setToPlace("MUMBAI");
        req.setTripType("ROUND_TRIP");
        req.setTravelDate(LocalDate.of(2025, 11, 25));
        req.setReturnDate(LocalDate.of(2025, 11, 28));

        var out = service.searchFlights(req).collectList().block();
        assertEquals("AE102", out.get(0).getReturnFlightNumber());
    }


    @Test
    void testAddInventorySuccess() {
        FlightInventoryRequest req = TestData.inventoryRequest();

        FlightInventory saved = TestData.flightBasic();

        when(repo.save(any())).thenReturn(Mono.just(saved));

        FlightInventory result = service.addInventory(req).block();

        assertNotNull(result);
        assertEquals("AE101", result.getFlightNumber());
    }

    @Test
    void testGetFlightByIdSuccess() {
        FlightInventory f = TestData.flightBasic();

        when(repo.findById("123")).thenReturn(Mono.just(f));

        var got = service.getFlightById("123").block();

        assertEquals("AE101", got.getFlightNumber());
    }

    @Test
    void testGetFlightByIdNotFound() {
        when(repo.findById("404")).thenReturn(Mono.empty());

        Exception ex = assertThrows(RuntimeException.class, () ->
                service.getFlightById("404").block()
        );

        assertEquals("Flight not found", ex.getMessage());
    }

    @Test
    void testReduceSeatsSuccess() {
        FlightInventory f = TestData.flightBasic();
        f.setAvailableSeats(50);

        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(10);


        when(repo.findById("100")).thenReturn(Mono.just(f));
        when(repo.save(any())).thenReturn(Mono.just(f));

        var result = service.reduceSeats("100", req).block();
        assertNull(result);
        assertEquals(40, f.getAvailableSeats());
    }

    @Test
    void testReduceSeatsInsufficientSeats() {
        FlightInventory f = TestData.flightBasic();
        f.setAvailableSeats(5);

        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(20);


        when(repo.findById("200")).thenReturn(Mono.just(f));

        Exception ex = assertThrows(RuntimeException.class, () ->
                service.reduceSeats("200", req).block()
        );

        assertEquals("Insufficient seats", ex.getMessage());
    }

    @Test
    void testReduceSeatsFlightNotFound() {
    	InventoryUpdateRequest req = new InventoryUpdateRequest();
    	req.setSeats(10);


        when(repo.findById("300")).thenReturn(Mono.empty());

        Exception ex = assertThrows(RuntimeException.class, () ->
                service.reduceSeats("300", req).block()
        );

        assertEquals("Flight not found", ex.getMessage());
    }

    @Test
    void testIncreaseSeatsSuccess() {
        FlightInventory f = TestData.flightBasic();
        f.setAvailableSeats(30);

        InventoryUpdateRequest req = new InventoryUpdateRequest();
        req.setSeats(20);


        when(repo.findById("500")).thenReturn(Mono.just(f));
        when(repo.save(any())).thenReturn(Mono.just(f));

        service.increaseSeats("500", req).block();

        assertEquals(50, f.getAvailableSeats());
    }

    @Test
    void testIncreaseSeatsFlightNotFound() {
    	InventoryUpdateRequest req = new InventoryUpdateRequest();
    	req.setSeats(10);

        when(repo.findById("999")).thenReturn(Mono.empty());

        Exception ex = assertThrows(RuntimeException.class, () ->
                service.increaseSeats("999", req).block()
        );

        assertEquals("Flight not found", ex.getMessage());
    }
}
