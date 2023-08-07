package com.dental.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.sql.Date;
import java.util.List;
import java.util.Set;

@Entity
@Data
public class Doctor {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer doctorId;

    @Column(nullable = false, columnDefinition = "text")
    @Size(min = 1, message = "Bio must be mandatory")
    private String description;

    @OneToMany(mappedBy = "doctor")
    private List<MedicalInformation> medicalInformation;

    @ManyToMany
    @JoinTable(
            name = "doctor_service",
            joinColumns = @JoinColumn(name = "doctor_id"),
            inverseJoinColumns = @JoinColumn(name = "service_id"))
    Set<Service> service;

    @OneToOne
    @MapsId
    @JoinColumn(name = "doctor_id")
    private User user;

    @OneToMany(mappedBy = "doctor")
    private List<Appointment> appointment;

    public Integer getDoctorId() {
        return doctorId;
    }

    public void setDoctorId(Integer doctorId) {
        this.doctorId = doctorId;
    }


    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "Doctor{" +
                "doctorId=" + doctorId +
                ", description='" + description + '\'' +
                ", medicalInformation=" + medicalInformation.size() +
                ", service=" + service.size() +
                ", user=" + user.getUserId() +
                '}';
    }
}
