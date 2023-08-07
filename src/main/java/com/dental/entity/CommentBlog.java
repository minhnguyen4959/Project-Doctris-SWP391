package com.dental.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Data
public class CommentBlog {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer commentId;

    @Column(nullable = false, columnDefinition = "text")
    @Size(min = 1, message = "Comment must be mandatory")
    private String description;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @ManyToOne
    @JoinColumn(name = "blog_id", nullable = false)
    private Blog blog;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

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

    @Override
    public String toString() {
        return "CommentBlog{" +
                "commentId=" + commentId +
                ", description='" + description + '\'' +
                ", createdAt=" + createdAt +
                ", blog=" + blog.getBlogId() +
                ", user=" + user.getUserId() +
                '}';
    }
}
