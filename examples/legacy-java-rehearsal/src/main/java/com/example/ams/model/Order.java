package com.example.ams.model;

public class Order {
    private long id;
    private long ownerId;
    private String item;
    private String note;
    private int total;

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public long getOwnerId() { return ownerId; }
    public void setOwnerId(long ownerId) { this.ownerId = ownerId; }
    public String getItem() { return item; }
    public void setItem(String item) { this.item = item; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
    public int getTotal() { return total; }
    public void setTotal(int total) { this.total = total; }
}
