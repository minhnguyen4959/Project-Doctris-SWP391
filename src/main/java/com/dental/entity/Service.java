package com.dental.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Date;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Data
public class Service {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer serviceId;

    @Column(nullable = false, columnDefinition = "nvarchar(100)")
    @Size(min = 1, max = 100, message = "Title must be mandatory and less than 100 characters")
    private String title;

    @Column(nullable = false, columnDefinition = "text")
    @Size(min = 1, max = 255, message = "Description must be mandatory and less than 255 characters")
    private String description;

    @Column(nullable = false, columnDefinition = "text")
    @Size(min = 1, message = "Content must be mandatory")
    private String content;

    @Column(nullable = false, columnDefinition = "text")
    private String thumbnail;

    @Column(nullable = false, length = 1, columnDefinition = "BIT(1) default 1")
    @NotNull(message = "Status must be mandatory")
    private boolean status;

    @Column(nullable = false)
    @NotNull(message = "Price must be mandatory")
    @DecimalMin(value = "1", message = "Price must be larger than 1")
    @DecimalMax(value = "20000000", message = "Price must be less than 20000000")
    @Pattern(regexp = "^[0-9]+(\\.[0-9]+)?$", message = "Price must be a valid number")
    private String price;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @ManyToMany(mappedBy = "service")
    private Set<Doctor> doctor;

//    @OneToMany(mappedBy = "service", cascade = CascadeType.ALL)
//    private List<MedicalInformation> medicalInformation;

    @OneToMany(mappedBy = "service", cascade = CascadeType.ALL)
    private List<RateStar> rateStar;

    @ManyToMany(mappedBy = "service")
    Set<Appointment> appointment = new HashSet<>();

    public Integer getServiceId() {
        return serviceId;
    }

    public void setServiceId(Integer serviceId) {
        this.serviceId = serviceId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getThumbnail() {
        return thumbnail;
    }

    public void setThumbnail(String thumbnail) {
        this.thumbnail = thumbnail;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    public Set<Doctor> getDoctor() {
        return doctor;
    }

    public void setDoctor(Set<Doctor> doctor) {
        this.doctor = doctor;
    }

//    public List<MedicalInformation> getMedicalInformation() {
//        return medicalInformation;
//    }
//
//    public void setMedicalInformation(List<MedicalInformation> medicalInformation) {
//        this.medicalInformation = medicalInformation;
//    }

    public List<RateStar> getRateStar() {
        return rateStar;
    }

    public void setRateStar(List<RateStar> rateStar) {
        this.rateStar = rateStar;
    }

    public Set<Appointment> getAppointment() {
        return appointment;
    }

    public void setAppointment(Set<Appointment> appointment) {
        this.appointment = appointment;
    }

    public Integer getAvgStarByServiceId(Integer serviceId,List<Object[]> servicesWithAVG){
        Double totalStar;
        for (Object[] serviceWithAVG :servicesWithAVG){
            if (serviceId == serviceWithAVG[0]){
                totalStar = (Double) serviceWithAVG[1];
                return  (int)(Math.round(totalStar));
            }
        }
        return 0;
    }

    @Override
    public String toString() {
        return "Service{" +
                "serviceId=" + serviceId +
                ", title='" + title + '\'' +
                ", description='" + description + '\'' +
                ", thumbnail='" + thumbnail + '\'' +
                ", status=" + status +
                ", price=" + price +
                ", doctor=" + doctor.size() +
                ", rateStar=" + rateStar.size() +
                ", appointment=" + appointment.size() +
                '}';
    }
}
