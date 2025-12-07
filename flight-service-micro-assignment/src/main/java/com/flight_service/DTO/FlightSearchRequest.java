package com.flight_service.DTO;
import java.time.LocalDate;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class FlightSearchRequest {
	
	@NotBlank(message = "From place is required")
    private String fromPlace;

    @NotBlank(message = "To place is required")
    private String toPlace;

    @NotNull(message = "Travel date is required")
    @Future(message = "Travel date must be a future date")
    private LocalDate travelDate;

    
    @Pattern(
        regexp = "^$|^([01]\\d|2[0-3]):([0-5]\\d)$",
        message = "Time must be in HH:mm format"
    )
    private String travelTime;
    
    @Pattern(
        regexp = "ONE_WAY|ROUND_TRIP",
        message = "Trip type must be ONE_WAY or ROUND_TRIP"
    )
    private String tripType; 
    
    @Future(message = "Return date must be a future date")
    private LocalDate returnDate; 
    
 

    
}


