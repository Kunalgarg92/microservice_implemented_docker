package com.booking_service.kafka;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import com.booking_service.event.BookingEvent;

@Service
public class BookingEventProducer {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final String topic;

    public BookingEventProducer(
            KafkaTemplate<String, Object> kafkaTemplate,
            @Value("${booking.kafka.topic}") String topic) {
        this.kafkaTemplate = kafkaTemplate;
        this.topic = topic;
    }

    public void publishBookingConfirmed(BookingEvent event) {
        kafkaTemplate.send(topic, event.getPnr(), event);

        System.out.println("📤 Booking Event Published to Kafka for PNR: " + event.getPnr());
    }
}
