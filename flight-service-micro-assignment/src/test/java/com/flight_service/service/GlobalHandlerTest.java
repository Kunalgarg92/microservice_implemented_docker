package com.flight_service.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.support.WebExchangeBindException;

import com.flight_service.exception.ErrrorResponse;
import com.flight_service.exception.GlobalErrorHandler;
import com.flight_service.exception.ResourceNotFoundException;

import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.core.MethodParameter;
import org.springframework.http.server.reactive.ServerHttpRequest;

import jakarta.validation.ConstraintViolationException;

class GlobalErrorHandlerTest {

    private final GlobalErrorHandler handler = new GlobalErrorHandler();
    static class Dummy {
        @SuppressWarnings("unused")
        public void method(String arg) {}
    }

    @Test
    void handleWebFluxValidation_returnsBadRequestWithFieldErrors() throws NoSuchMethodException {
        Object target = new Object();
        BeanPropertyBindingResult result =
                new BeanPropertyBindingResult(target, "bookingRequest");
        result.addError(new FieldError("bookingRequest", "email", "Invalid email"));

        MethodParameter param =
                new MethodParameter(Dummy.class.getMethod("method", String.class), 0);

        WebExchangeBindException ex = new WebExchangeBindException(param, result);
        ServerHttpRequest request =
                MockServerHttpRequest.post("/api/v1.0/flight/booking/1").build();
        ResponseEntity<Object> response =
                handler.handleWebFluxValidation(ex, request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();

        ErrrorResponse err = (ErrrorResponse) body.get("errorResponse");
        @SuppressWarnings("unchecked")
        Map<String, String> fieldErrors = (Map<String, String>) body.get("errors");

        assertEquals(400, err.getStatus());
        assertEquals("Bad Request", err.getError());
        assertEquals("/api/v1.0/flight/booking/1", err.getPath());
        assertEquals("Invalid email", fieldErrors.get("email"));
    }

    @Test
    void handleMethodArgumentNotValid_returnsBadRequest() throws NoSuchMethodException {
        Object target = new Object();
        BeanPropertyBindingResult result =
                new BeanPropertyBindingResult(target, "obj");
        result.addError(new FieldError("obj", "email", "must not be blank"));

        MethodParameter param =
                new MethodParameter(Dummy.class.getMethod("method", String.class), 0);

        MethodArgumentNotValidException ex =
                new MethodArgumentNotValidException(param, result);

        ServerHttpRequest request =
                MockServerHttpRequest.post("/test").build();

        ResponseEntity<Object> response =
                handler.handleValidationErrors(ex, request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        ErrrorResponse err = (ErrrorResponse) body.get("errorResponse");

        assertEquals(400, err.getStatus());
        assertEquals("Bad Request", err.getError());
        assertEquals("/test", err.getPath());
    }

    @Test
    void handleConstraintViolations_returnsBadRequest() {
        ConstraintViolationException ex =
                new ConstraintViolationException("some violation", Collections.emptySet());

        ServerHttpRequest request =
                MockServerHttpRequest.get("/constraint").build();

        ResponseEntity<ErrrorResponse> response =
                handler.handleConstraintViolations(ex, request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrrorResponse err = response.getBody();
        assertNotNull(err);
        assertEquals(400, err.getStatus());
        assertEquals("Bad Request", err.getError());
        assertEquals("/constraint", err.getPath());
    }
    
    @Test
    void handleNotReadable_withSpecificCause_usesCauseMessage() {
        GlobalErrorHandler handler = new GlobalErrorHandler();

        HttpMessageNotReadableException ex =
                new HttpMessageNotReadableException(
                       "outer",
                       new RuntimeException("inner-cause"),
                       (HttpInputMessage) null
                );


        ServerHttpRequest req = MockServerHttpRequest.post("/test").build();

        ResponseEntity<ErrrorResponse> response =
                handler.handleNotReadable(ex, req);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("inner-cause", response.getBody().getMessage());
    }


    @Test
    void handleNotReadable_withoutSpecificCause_usesDefaultMessage() {
        HttpMessageNotReadableException ex =
                new HttpMessageNotReadableException("bad json", (HttpInputMessage) null);

        ServerHttpRequest request =
                MockServerHttpRequest.post("/not-readable").build();

        ResponseEntity<ErrrorResponse> response =
                handler.handleNotReadable(ex, request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrrorResponse err = response.getBody();
        assertNotNull(err);
        assertEquals(400, err.getStatus());
        assertEquals("Bad Request", err.getError());
        assertEquals("/not-readable", err.getPath());
        assertEquals("bad json", err.getMessage());
    }
    
    @Test
    void handleIllegalArg_returnsBadRequest() {
        IllegalArgumentException ex =
                new IllegalArgumentException("invalid argument");

        ServerHttpRequest request =
                MockServerHttpRequest.get("/illegal").build();

        ResponseEntity<ErrrorResponse> response =
                handler.handleIllegalArg(ex, request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrrorResponse err = response.getBody();
        assertNotNull(err);
        assertEquals(400, err.getStatus());
        assertEquals("Bad Request", err.getError());
        assertEquals("invalid argument", err.getMessage());
        assertEquals("/illegal", err.getPath());
    }

    @Test
    void handleNPE_returnsInternalServerError() {
        NullPointerException ex = new NullPointerException();

        ServerHttpRequest request =
                MockServerHttpRequest.get("/npe").build();

        ResponseEntity<ErrrorResponse> response =
                handler.handleNPE(ex, request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ErrrorResponse err = response.getBody();
        assertNotNull(err);
        assertEquals(500, err.getStatus());
        assertEquals("Internal Server Error", err.getError());
        assertEquals("A required value was missing or an unexpected null occurred",
                     err.getMessage());
        assertEquals("/npe", err.getPath());
    }

    @Test
    void handleAll_returnsInternalServerError() {
        Exception ex = new Exception("boom");

        ServerHttpRequest request =
                MockServerHttpRequest.get("/generic").build();

        ResponseEntity<ErrrorResponse> response =
                handler.handleAll(ex, request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ErrrorResponse err = response.getBody();
        assertNotNull(err);
        assertEquals(500, err.getStatus());
        assertEquals("Internal Server Error", err.getError());
        assertEquals("boom", err.getMessage());
        assertEquals("/generic", err.getPath());
    }

    @Test
    void handleNotFound_returns404() {
        ResourceNotFoundException ex = new ResourceNotFoundException("Booking not found");
        ServerHttpRequest request =
                MockServerHttpRequest.get("/ticket/PNR123").build();
        ResponseEntity<ErrrorResponse> response =
                handler.handleNotFound(ex, request);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        ErrrorResponse err = response.getBody();
        assertNotNull(err);
        assertEquals(404, err.getStatus());
        assertEquals("Not Found", err.getError());
        assertEquals("Booking not found", err.getMessage());
        assertEquals("/ticket/PNR123", err.getPath());
    }
}
