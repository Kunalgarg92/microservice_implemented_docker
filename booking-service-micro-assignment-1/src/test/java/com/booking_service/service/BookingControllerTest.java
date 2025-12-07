package com.booking_service.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.booking_service.Controller.BookingController;
import com.booking_service.DTO.BookingResponse;
import com.booking_service.exception.GlobalErrorHandler;
import com.booking_service.service.BookingService;
import org.springframework.boot.test.mock.mockito.MockBean;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@WebFluxTest(controllers = BookingController.class)
@Import(GlobalErrorHandler.class)
class BookingControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private BookingService bookingService;

    @Test
    void postBooking_validation_error() {
        String invalidBody = """
            {
              "email":"a@b.com",
              "numberOfSeats":2,
              "passengers":[]
            }
            """;

        webTestClient.post()
                .uri("/api/flight/booking/1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(invalidBody)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void postBooking_success_returns201() {   // 🔥 FIXED: expect CREATED
        BookingResponse resp = new BookingResponse();
        resp.setPnr("ABC123");

        Mockito.when(bookingService.bookFlight(eq("1"), any()))
               .thenReturn(Mono.just(resp));

        String validBody = """
            {
              "email":"a@b.com",
              "numberOfSeats":1,
              "passengers":[
                {
                  "fareCategory":"STUDENT",
                  "name":"A",
                  "gender":"MALE",
                  "age":20,
                  "meal":"VEG",
                  "seatNumber":10
                }
              ]
            }
            """;

        webTestClient.post()
                .uri("/api/flight/booking/1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody)
                .exchange()
                .expectStatus().isCreated()     // 🔥 FIXED: BookingController returns 201
                .expectBody()
                .jsonPath("$.pnr").isEqualTo("ABC123");
    }

    @Test
    void testGetHistory() {
        Mockito.when(bookingService.getBookingHistory("abc@gmail.com"))
               .thenReturn(Flux.just(new BookingResponse()));

        webTestClient.get()
                .uri("/api/flight/booking/history/abc@gmail.com")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void cancelBooking_success() {
        Mockito.when(bookingService.cancelBooking("PNR123"))
               .thenReturn(Mono.empty());

        webTestClient.delete()
                .uri("/api/flight/booking/cancel/PNR123")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .isEqualTo("Ticket with PNR PNR123 has been cancelled successfully.");
    }
}
