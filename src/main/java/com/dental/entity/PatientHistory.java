package com.dental.entity;

import jakarta.persistence.*;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.sql.Date;
import java.util.List;

@Entity
@Data
public class PatientHistory {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer patientHistoryId;

    @Column(nullable = false)
    @Size(min = 1, message = "Temperature must be mandatory")
    @Pattern(regexp = "\\d{2}(?:\\.\\d)?", message = "Wrong type of temperature")
    private String temperature;

    @Column(nullable = false)
    @Size(min = 1, message = "Blood pressure must be mandatory")
    @Pattern(regexp = "^\\d{2,3}/\\d{2,3}$", message = "Wrong type of blood pressure")
    private String bloodPressure;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean liver;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean diabetes;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean rheumatism;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean nerve;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean allergy;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean digest;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean respiratory;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean cardiovascular;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean kidney;

    @Column(nullable = false, columnDefinition = "text")
    private String other1;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean temporomandibularJoint;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean toothExtraction;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean orthodonticTreatment;

    @Column(nullable = false, columnDefinition = "BIT(1) default 0")
    private boolean dentalBraces;

    @Column(nullable = false, columnDefinition = "text")
    private String other2;

    @Column(nullable = false)
    private Date date;

    @Column(nullable = false, columnDefinition = "text")
    @Size(min = 1, message = "Prediction must be mandatory")
    private String note;

//    @OneToMany(mappedBy = "patientHistory")
//    private List<MedicalInformation> medicalInformation;

//    @ManyToOne
//    @JoinColumn(name = "patient_id", nullable = false)
//    private Patient patient;

    @OneToOne
    @MapsId
    @JoinColumn(name = "patient_history_id")
    private Appointment appointment;

//    @OneToOne(mappedBy = "patient_history")
//    @PrimaryKeyJoinColumn
//    private Appointment appointment;
}
