package com.booking_service.kafka;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import com.booking_service.event.BookingEvent;
import com.booking_service.email.EmailService;

@Component
public class BookingEventConsumer {

    private final EmailService emailService;

    public BookingEventConsumer(EmailService emailService) {
        this.emailService = emailService;
    }

    @KafkaListener(
            topics = "${booking.kafka.topic}",
            groupId = "booking-service-group",
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeBookingEvent(BookingEvent event) {

        System.out.println(" Received Booking Event for PNR: " + event.getPnr());

        String subject = "Your Flight Booking is Confirmed | PNR: " + event.getPnr();

        String htmlBody = buildEmailBody(event);

        emailService.sendBookingEmail(event.getEmail(), subject, htmlBody);
    }

    private String buildEmailBody(BookingEvent event) {

        StringBuilder sb = new StringBuilder();

        sb.append("<h2>Flight Booking Confirmed </h2>");
        sb.append("<p>Your PNR: <b>").append(event.getPnr()).append("</b></p>");
        sb.append("<p>Total Seats: ").append(event.getNumberOfSeats()).append("</p>");
        sb.append("<p>Total Price: <b>").append(event.getTotalPrice()).append("</b></p>");
        sb.append("<hr/>");
        sb.append("<h3>Passenger Details</h3><ul>");

        for (BookingEvent.PassengerInfo p : event.getPassengers()) {
            sb.append("<li>")
                    .append("<b>").append(p.getName()).append("</b>")
                    .append(" | Seat: ").append(p.getSeatNumber())
                    .append(" | Meal: ").append(p.getMeal())
                    .append(" | Fare: ").append(p.getFareCategory())
                    .append("</li>");
        }

        sb.append("</ul>");
        sb.append("<p>Thank you for booking with us! ✈</p>");

        return sb.toString();
    }
}

