package com.dental.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

@Entity
@Data
public class Blog {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer blogId;

    @Column(length = 254, nullable = false, columnDefinition = "nvarchar(254)")
    @Size(min = 1, max = 254, message = "Title must be mandatory and less than 254 characters")
    private String title;

    @Column(length = 254, nullable = true)
    @Size(max = 254, message = "Thumbnail must be less than 254 characters")
    private String thumbnail;

    @Column(columnDefinition = "nvarchar(255)", nullable = false)
    @Size(min = 1, max = 255, message = "Summary must be mandatory and less than 255 characters")
    private String summary;

    @Column(nullable = true, columnDefinition = "text")
    @Size(min = 1, message = "Content must be mandatory")
    private String content;

    @Column(length = 1, nullable = false, columnDefinition = "BIT(1) default 1")
    @NotNull(message = "Status must be mandatory")
    private boolean status;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(mappedBy = "blog", cascade = CascadeType.ALL)
    private List<CommentBlog> commentBlog;

    public Integer getBlogId() {
        return blogId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getThumbnail() {
        return thumbnail;
    }

    public void setThumbnail(String thumbnail) {
        this.thumbnail = thumbnail;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

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

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public List<CommentBlog> getCommentBlog() {
        return commentBlog;
    }

    public void setCommentBlog(List<CommentBlog> commentBlog) {
        this.commentBlog = commentBlog;
    }

    @Override
    public String toString() {
        String pattern = "MMMM dd yyyy";
        Date date = null;
        String d = null;
        if (String.valueOf(createdAt).isEmpty()) {
            try {
                date = new SimpleDateFormat("yyyy-MM-dd").parse(createdAt.toString());
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
            d = simpleDateFormat.format(date);
        }
//        createdAt = LocalDateTime.parse(d);

        return "Blog{" +
                "blogId=" + blogId +
                ", title='" + title + '\'' +
                ", thumbnail='" + thumbnail + '\'' +
                ", summary='" + summary + '\'' +
                ", content='" + content + '\'' +
                ", status=" + status +
                ", createdAt=" + d +
                ", user=" + user.getUserId() +
                ", commentBlog=" + commentBlog.size() +
                '}';
    }
}
