package com.booking_service.service;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.reactive.server.WebTestClient;
import com.booking_service.Controller.TicketController;
import com.booking_service.DTO.BookingResponse;
import com.booking_service.exception.GlobalErrorHandler;
import com.booking_service.exception.ResourceNotFoundException;

import reactor.core.publisher.Mono;

@WebFluxTest(controllers = TicketController.class)
@Import(GlobalErrorHandler.class)
class TicketControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private BookingService bookingService;

    @Test
    void getTicket_success() {
        BookingResponse resp = new BookingResponse();
        resp.setPnr("ABC123");
        resp.setEmail("a@b.com");

        when(bookingService.getBookingByPnr(eq("ABC123")))
                .thenReturn(Mono.just(resp));

        webTestClient.get()
                .uri("/api/flight/ticket/ABC123")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.pnr").isEqualTo("ABC123")
                .jsonPath("$.email").isEqualTo("a@b.com");
    }

    @Test
    void getTicket_notFound() {
        when(bookingService.getBookingByPnr(eq("PNR999")))
                .thenReturn(Mono.error(
                        new ResourceNotFoundException("Booking with PNR 'PNR999' not found")));

        webTestClient.get()
                .uri("/api/flight/ticket/PNR999")
                .exchange()
                .expectStatus().isNotFound();
    }
}

