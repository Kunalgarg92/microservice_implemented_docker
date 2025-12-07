package com.booking_service.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import com.booking_service.Model.Passenger;

import reactor.core.publisher.Flux;

@Repository
public interface PassengerRepository extends ReactiveMongoRepository<Passenger, String> {

    @Query("""
        {
            'bookingId': ?0,
            'seatNumber': { $in: ?1 }
        }
    """)
    Flux<Passenger> findBookedSeatsForFlight(String bookingId, List<Integer> seats);

    Flux<Passenger> findByBookingId(String bookingId);
}
