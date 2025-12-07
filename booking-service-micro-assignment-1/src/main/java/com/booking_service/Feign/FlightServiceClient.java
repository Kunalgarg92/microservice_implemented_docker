package com.booking_service.Feign;
import com.booking_service.DTO.FlightResponseDto;
import com.booking_service.DTO.InventoryUpdateRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(
	    name = "flight-service-micro-assignment",
	    fallback = FlightServiceFallback.class
	)

public interface FlightServiceClient {

    @GetMapping("/api/flight/internal/{flightId}")
    FlightResponseDto getFlightById(@PathVariable String flightId);

    @PostMapping("/api/flight/internal/{flightId}/inventory/reduce")
    void reduceSeats(@PathVariable String flightId,
                     @RequestBody InventoryUpdateRequest request);

    @PostMapping("/api/flight/internal/{flightId}/inventory/increase")
    void increaseSeats(@PathVariable String flightId,
                       @RequestBody InventoryUpdateRequest request);
}

