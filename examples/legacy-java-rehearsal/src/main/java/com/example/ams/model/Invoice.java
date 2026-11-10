package com.example.ams.model;

public class Invoice {
    private long id;
    private long ownerId;
    private int amount;

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public long getOwnerId() { return ownerId; }
    public void setOwnerId(long ownerId) { this.ownerId = ownerId; }
    public int getAmount() { return amount; }
    public void setAmount(int amount) { this.amount = amount; }
}
