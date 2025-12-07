package com.booking_service.Controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import com.booking_service.DTO.BookingResponse;
import com.booking_service.service.BookingService;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/flight")
public class TicketController {
	
    @Autowired
    private BookingService bookingService;
    @GetMapping("/ticket/{pnr}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<BookingResponse> getTicketByPnr(@PathVariable("pnr") String pnr) {
        return bookingService.getBookingByPnr(pnr); 
    }
}
