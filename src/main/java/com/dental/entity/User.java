package com.dental.entity;

import com.dental.util.AgeConstraint;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

@Entity
@Data
public class User {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer userId;

    @Column(length = 254, nullable = false, unique = true)
    @Size(min = 1, max = 254, message = "Email must be mandatory and less than 254 characters")
    @Email(message = "This field must be an email")
    private String email;

    @Column(length = 254, nullable = false)
    private String password;

    @Column(nullable = true, columnDefinition = "nvarchar(8)")
    @Size(min = 1, max = 8, message = "Gender must be mandatory and less than 8 characters")
    private String gender;

    @Column(nullable = true)
    private java.sql.Date dateOfBirth;

    @Column(nullable = true, columnDefinition = "nvarchar(100)")
    @Size(min = 1, max = 100, message = "Address must be mandatory and less than 100 characters")
    private String address;

    @Column(nullable = true, length = 12)
    @Size(min = 10, max = 12, message = "Phone must be mandatory and less than 12 characters")
    @Pattern(regexp = "^(?:\\+)?[0-9]*$", message = "Wrong type of phone number")
    private String phoneNumber;

    @Column(nullable = true, columnDefinition = "text")
    private String avatar;

    @Column(columnDefinition = "nvarchar(50)" , nullable = false)
    @Size(min = 6, max = 50, message = "Full name must be mandatory and less than 50 characters")
    @Pattern(regexp = "^[\\p{L}\\s]+$", message = "Full name must not contain special character and not empty")
    private String fullName;

    @Column(length = 1, nullable = false, columnDefinition = "bit default 1")
    private boolean status;

    @Column(length = 20, nullable = false, columnDefinition = "nvarchar(20) default 'Patient'")
    @Pattern(regexp = "Admin|Patient|Doctor|Staff", message = "Role undefined")
    @Size(max = 20, message = "Role must be less than 20 characters")
    private String role;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(length = 6, nullable = true)
    private String captcha;

    @Column(nullable = true)
    private Date captchaExpire;

    @OneToMany(mappedBy = "user")
    private List<Blog> blog;

    @OneToMany(mappedBy = "user")
    private List<CommentBlog> commentBlog;

    @OneToMany(mappedBy = "user")
    private List<RateStar> rateStar;

    @OneToOne(mappedBy = "user")
    @PrimaryKeyJoinColumn
    private Doctor doctor;

    @OneToOne(mappedBy = "user")
    @PrimaryKeyJoinColumn
    private Patient patient;

    @Column(nullable = true)
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public java.sql.Date getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(java.sql.Date dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    @Override
    public String toString() {
        return "User{" +
                "userId=" + userId +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", fullName='" + fullName + '\'' +
                ", status=" + status +
                ", role='" + role + '\'' +
                ", createdAt=" + createdAt +
                ", captcha='" + captcha + '\'' +
                ", captchaExpire=" + captchaExpire +
                '}';
    }
}
