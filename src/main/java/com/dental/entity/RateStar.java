package com.dental.entity;

import jakarta.persistence.*;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Data
public class RateStar {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer rateStarId;

    @Column(nullable = false)
    @NotNull(message = "Star must be mandatory")
    private float star;

    @Column(nullable = false, columnDefinition = "text")
    @Size(min = 1, message = "Feedback must be mandatory")
    private String feedback;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "service_id", nullable = false)
    private Service service;

    public String getCreatedAt() {
        String pattern = "MMMM dd yyyy";
        Date date = null;
        String d = null;
        try {
            date = new SimpleDateFormat("yyyy-MM-dd").parse(createdAt.toString());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        d = simpleDateFormat.format(date);
        return d;
    }

    public LocalDateTime getCreatedAt(String s) {
        return createdAt;
    }

    public RateStar() {
    }

    public RateStar(float star, String feedback, User user, Service service) {
        this.star = star;
        this.feedback = feedback;
        this.user = user;
        this.service = service;
    }

    @Override
    public String toString() {
        return "RateStar{" +
                "rateStarId=" + rateStarId +
                ", star=" + star +
                ", feedback='" + feedback + '\'' +
                ", createdAt=" + createdAt +
                ", user=" + user.getUserId() +
                ", service=" + service.getServiceId() +
                '}';
    }
}
