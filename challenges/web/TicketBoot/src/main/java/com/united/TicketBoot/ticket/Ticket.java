package com.united.TicketBoot.ticket;

import jakarta.validation.constraints.NotBlank;

public class Ticket {

    private String id;

    @NotBlank(message = "Name cannot be empty.")
    private String name;

    private String couponCode;

    private String flag;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCouponCode() {
        return couponCode;
    }

    public void setCouponCode(String couponCode) {
        this.couponCode = couponCode;
    }

    public String getFlag() {
        return flag;
    }

    public void setFlag(String flag) {
        this.flag = flag;
    }
}
