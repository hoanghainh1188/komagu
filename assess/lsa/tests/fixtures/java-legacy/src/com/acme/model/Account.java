package com.acme.model;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Account {
    @Id
    private Long id;
    private String name;
    private String role;
    private Long balance;
}
