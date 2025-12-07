package com.booking_service.DTO;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PassengerRequest {
	@NotBlank(message = "Passenger category is required")
	    private String fareCategory;
	
	@NotBlank(message = "Passenger name is required")
    private String name;

    @NotBlank(message = "Gender is required")
    @Pattern(regexp = "MALE|FEMALE|OTHER", message = "Gender must be MALE, FEMALE or OTHER")
    private String gender;

    @Min(value = 0, message = "Age must be >= 0")
    private int age;

    @NotBlank(message = "Meal choice required")
    @Pattern(regexp = "VEG|NON_VEG", message = "Meal must be VEG or NON_VEG")
    private String meal;

    @NotNull(message = "Seat number is required")
    @Min(value = 1, message = "Seat number must be >= 1")
    private Integer seatNumber;
}

