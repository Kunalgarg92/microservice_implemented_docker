package com.flight_service.repository;
import com.flight_service.Model.FlightInventory;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import java.time.LocalDateTime;

@Repository
public interface FlightInventoryRepository extends ReactiveMongoRepository<FlightInventory, String> {

    Flux<FlightInventory> findByFromPlaceIgnoreCaseAndToPlaceIgnoreCaseAndDepartureTimeBetween(
            String fromPlace,
            String toPlace,
            LocalDateTime start,
            LocalDateTime end
    );
}
