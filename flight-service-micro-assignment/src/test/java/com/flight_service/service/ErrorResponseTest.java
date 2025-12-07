package com.flight_service.service;


import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import com.flight_service.exception.ErrrorResponse;

class ErrrorResponseTest {

    @Test
    void noArgConstructor_and_setters_getters() {
        ErrrorResponse er = new ErrrorResponse();

        assertNull(er.getTimestamp(), "timestamp should be null for no-arg constructor");

        Instant now = Instant.now();
        er.setTimestamp(now);
        er.setStatus(500);
        er.setError("Internal Server Error");
        er.setMessage("Something went wrong");
        er.setPath("/api/test");

        // Validate getters
        assertEquals(now, er.getTimestamp());
        assertEquals(500, er.getStatus());
        assertEquals("Internal Server Error", er.getError());
        assertEquals("Something went wrong", er.getMessage());
        assertEquals("/api/test", er.getPath());
    }

    @Test
    void parameterizedConstructor_setsFields_and_timestampIsNowBetweenBounds() {
        Instant before = Instant.now();

        ErrrorResponse er = new ErrrorResponse(
                404,
                "Not Found",
                "Resource missing",
                "/api/missing"
        );

        Instant after = Instant.now();

        assertEquals(404, er.getStatus());
        assertEquals("Not Found", er.getError());
        assertEquals("Resource missing", er.getMessage());
        assertEquals("/api/missing", er.getPath());

        assertNotNull(er.getTimestamp(), "timestamp should be set by parameterized constructor");
        Instant ts = er.getTimestamp();
        assertFalse(ts.isBefore(before), "timestamp should not be before the moment just before construction");
        assertFalse(ts.isAfter(after), "timestamp should not be after the moment just after construction");
    }

    @Test
    void setTimestamp_overwritesValue() {
        ErrrorResponse er = new ErrrorResponse();
        Instant t1 = Instant.now();
        Instant t2 = t1.plus(Duration.ofSeconds(30));

        er.setTimestamp(t1);
        assertEquals(t1, er.getTimestamp());

        er.setTimestamp(t2);
        assertEquals(t2, er.getTimestamp());
    }
}

