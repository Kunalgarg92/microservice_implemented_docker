package com.Eureka;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SpringBootTest
class EurekaServerRegistryFlightappApplicationTests {

    @Test
    void mainMethodRunsSuccessfully() {
        assertDoesNotThrow(() -> 
            EurekaServerRegistryFlightappApplication.main(new String[]{})
        );
    }
}
