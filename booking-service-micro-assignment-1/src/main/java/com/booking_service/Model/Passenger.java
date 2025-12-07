package com.booking_service.Model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import lombok.Data;

@Data
@Document(collection = "passenger")
public class Passenger {

    @Id
    private String id;

    @Field("name")
    private String name;

    @Field("gender")
    private String gender;

    @Field("age")
    private int age;

    @Field("meal")
    private String meal;

    @Field("seat_number")
    private int seatNumber;

    @Field("booking_id")
    private String bookingId; 

    @Field("fare_category")
    private String fareCategory;

    @Field("fare_applied")
    private double fareApplied;

    @Field("fare_message")
    private String fareMessage;

}
