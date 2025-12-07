package com.booking_service.service;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.boot.SpringApplication;

import com.booking_service.BookingServiceMicroAssignment1Application;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class BookingServiceMicroAssignment1ApplicationTest {

    @Test
    void mainMethod_runsSuccessfully_withoutStartingServer() {

        try (MockedStatic<SpringApplication> mocked = Mockito.mockStatic(SpringApplication.class)) {

            mocked.when(() ->
                    SpringApplication.run(BookingServiceMicroAssignment1Application.class, new String[]{})
            ).thenReturn(null);

            assertDoesNotThrow(() ->
            BookingServiceMicroAssignment1Application.main(new String[]{})
            );
        }
    }
}
