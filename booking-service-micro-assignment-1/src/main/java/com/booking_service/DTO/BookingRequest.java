package com.booking_service.DTO;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import java.util.List;

@Data
public class BookingRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email")
    private String email;
    @NotEmpty(message = "At least one passenger required")
    @Valid
    private List<PassengerRequest> passengers;
    @Min(value = 1, message = "Number of seats must be at least 1")
    private int numberOfSeats;
}
