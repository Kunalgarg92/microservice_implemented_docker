package com.flight_service;

import org.springframework.boot.SpringApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;
import jakarta.annotation.PostConstruct;
@SpringBootApplication
@PropertySource("classpath:application.properties")
public class FlightServiceMicroAssignmentApplication {

	public static void main(String[] args) {
		SpringApplication.run(FlightServiceMicroAssignmentApplication.class, args);
	}
}
