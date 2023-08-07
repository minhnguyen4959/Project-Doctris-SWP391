package com.dental.entity;

import com.dental.util.DateConstraint;
import com.dental.util.TimeConstraint;
import jakarta.persistence.*;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.sql.Time;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.sql.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Data
public class Appointment {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer appointmentId;

    @Column(nullable = false)
    @DateConstraint(message = "Date is mandatory")
    private Date date;

    @Column(nullable = false)
    @Pattern(regexp = "Morning|Afternoon", message = "Time undefined")
    private String time;

    @Column(nullable = false, length = 10, columnDefinition = "varchar(10) default 'New'")
    @Pattern(regexp = "New|Assigned|Completed|Cancel", message = "Status undefined")
    private String status;

    @Column(nullable = true, columnDefinition = "text")
    private String note;

    @ManyToMany(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(
            name = "appointment_detail",
            joinColumns = @JoinColumn(name = "appointment_id"),
            inverseJoinColumns = @JoinColumn(name = "service_id")
    )
    private List<Service> service;

    @ManyToOne
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @ManyToOne
    @JoinColumn(name = "doctor_id", nullable = true)
    private Doctor doctor;

    @OneToOne(mappedBy = "appointment")
    @PrimaryKeyJoinColumn
    private PatientHistory patientHistory;

//    @OneToOne
//    @MapsId
//    @JoinColumn(name = "appointment_id")
//    private PatientHistory patientHistory;

    public String getDateString() {
        return String.valueOf(date);
    }

    public Patient getPatient() {
        return patient;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        System.out.println("vcjhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh");
        System.out.println(date);
        this.date = date;
    }

    public String getDate(String s) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("MMMM dd yyyy");
        return dateFormat.format(date);
    }



//    public String getDate() {
//        String pattern = "MMMM dd yyyy";
//        java.util.Date cdate = null;
//        String d = null;
//        try {
//            cdate = new SimpleDateFormat("yyyy-MM-dd").parse(date.toString());
//        } catch (ParseException e) {
//            throw new RuntimeException(e);
//        }
//        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
//        d = simpleDateFormat.format(cdate);
//        return d;
//    }
//
//    public java.util.Date getDate(String s) {
//        return date;
//    }

//    public Set<Service> getService() {
//        return service;
//    }
}
