package com.flight_service.DTO;

import lombok.Data;

@Data
public class InventoryUpdateRequest {
    private int seats;
    private String reason;
    private String bookingId;
}
