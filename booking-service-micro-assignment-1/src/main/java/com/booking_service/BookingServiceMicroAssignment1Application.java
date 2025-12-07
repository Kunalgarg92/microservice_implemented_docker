package com.booking_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients(basePackages = "com.booking_service.Feign")
public class BookingServiceMicroAssignment1Application {
	public static void main(String[] args) {
		SpringApplication.run(BookingServiceMicroAssignment1Application.class, args);
	}
}
