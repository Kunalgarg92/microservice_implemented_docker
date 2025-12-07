package com.flight_service.exception;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import org.springframework.http.server.reactive.ServerHttpRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.web.bind.support.WebExchangeBindException;



@RestControllerAdvice
public class GlobalErrorHandler {
	  private static final String BAD_REQUEST = "Bad Request";
	@ExceptionHandler(WebExchangeBindException.class)
	public ResponseEntity<Object> handleWebFluxValidation(WebExchangeBindException ex, ServerHttpRequest request) {

	    Map<String, String> fieldErrors = new HashMap<>();

	    ex.getFieldErrors().forEach(err -> {
	        fieldErrors.put(err.getField(), err.getDefaultMessage());
	    });

	    String joined = fieldErrors.entrySet().stream()
	            .map(e -> e.getKey() + ": " + e.getValue())
	            .collect(Collectors.joining("; "));

	    ErrrorResponse body = new ErrrorResponse(
	            HttpStatus.BAD_REQUEST.value(),
	            BAD_REQUEST ,
	            joined,
	            request.getURI().getPath()
	    );

	    Map<String, Object> response = new HashMap<>();
	    response.put("errorResponse", body);
	    response.put("errors", fieldErrors);

	    return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
	}

	
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleValidationErrors(MethodArgumentNotValidException ex,ServerHttpRequest request
) {
        Map<String, String> fieldErrors = new HashMap<>();
        List<ObjectError> errorList = ex.getBindingResult().getAllErrors();
        errorList.forEach(error -> {
            if (error instanceof FieldError) {
                String fieldName = ((FieldError) error).getField();
                String msg = error.getDefaultMessage();
                fieldErrors.put(fieldName, msg);
            }
        });
        String joined = fieldErrors.entrySet().stream()
                .map(e -> e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining("; "));

        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                BAD_REQUEST ,
                joined,
                request.getURI().getPath()

        );
        Map<String, Object> response = new HashMap<>();
        response.put("errorResponse", body);
        response.put("errors", fieldErrors);

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrrorResponse> handleConstraintViolations(ConstraintViolationException ex,
    		ServerHttpRequest request) {
        String msg = ex.getConstraintViolations().stream()
                .map(cv -> cv.getMessage())
                .collect(Collectors.joining("; "));
        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                BAD_REQUEST ,
                msg,
                request.getURI().getPath()

        );
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    private static final String MALFORMED_JSON = "Malformed JSON or invalid field type";

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrrorResponse> handleNotReadable(
            HttpMessageNotReadableException ex, ServerHttpRequest request) {
        
        Throwable root = ex.getMostSpecificCause();
        String msg;

        if (root == null || root.getMessage() == null || root.getMessage().isBlank()) {
            msg = MALFORMED_JSON;
        } else {
            msg = root.getMessage();
        }

        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                BAD_REQUEST,
                msg,
                request.getURI().getPath()
        );

        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrrorResponse> handleIllegalArg(IllegalArgumentException ex,ServerHttpRequest request) {
        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                BAD_REQUEST ,
                ex.getMessage(),
                request.getURI().getPath()
        );
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ErrrorResponse> handleNPE(NullPointerException ex, ServerHttpRequest request
) {
        ex.printStackTrace(); 
        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "A required value was missing or an unexpected null occurred",
                request.getURI().getPath()

        );
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrrorResponse> handleAll(Exception ex, ServerHttpRequest request) {
        ex.printStackTrace(); 
        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                ex.getMessage() != null ? ex.getMessage() : "Unexpected error",
                		 request.getURI().getPath()
        );
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    
    
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrrorResponse> handleNotFound(ResourceNotFoundException ex, ServerHttpRequest request
) {
        ErrrorResponse body = new ErrrorResponse(
                HttpStatus.NOT_FOUND.value(),
                "Not Found",
                ex.getMessage(),
                request.getURI().getPath()

        );
        return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
        }
   
}
