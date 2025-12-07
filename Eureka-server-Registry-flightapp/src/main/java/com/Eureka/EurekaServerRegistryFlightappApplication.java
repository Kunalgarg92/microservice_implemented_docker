package com.Eureka;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class EurekaServerRegistryFlightappApplication {

	public static void main(String[] args) {
		SpringApplication.run(EurekaServerRegistryFlightappApplication.class, args);
	}

}
