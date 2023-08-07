package com.dental.repository;

import com.dental.entity.Appointment;
import com.dental.entity.Doctor;
import com.dental.entity.PatientHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Date;
import java.util.List;

@Repository
public interface PatientHistoryRepository extends JpaRepository<PatientHistory, Integer> {
    @Transactional
    @Modifying
    @Query(value = "UPDATE patient_history p SET p.temperature = ?1, p.blood_pressure = ?2, p.liver = ?3, p.diabetes = ?4, p.rheumatism = ?5, p.nerve = ?6, p.allergy = ?7, p.digest = ?8, p.respiratory = ?9, p.cardiovascular = ?10, p.kidney = ?11, p.other1 = ?12, p.temporomandibular_joint = ?13, p.tooth_extraction = ?14, p.orthodontic_treatment = ?15, p.dental_braces = ?16, p.other2 = ?17, p.date = ?18, p.note = ?19 WHERE p.patient_history_id = ?20", nativeQuery = true)
    void updatePatientHistory(String temperature, String bloodPressure, boolean liver, boolean diabetes, boolean rheumatism, boolean nerve, boolean allergy, boolean digest, boolean respiratory, boolean cardiovascular, boolean kidney, String other1, boolean temporomandibularJoint, boolean toothExtraction, boolean orthodonticTreatment, boolean dentalBraces, String other2, Date date, String note, int appointmentId);
}
