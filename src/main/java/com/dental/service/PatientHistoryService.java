package com.dental.service;

import com.dental.entity.PatientHistory;
import com.dental.repository.PatientHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.util.List;

@Service
public class PatientHistoryService {

    @Autowired
    PatientHistoryRepository patientHistoryRepository;

    public PatientHistory get(int id) {
        return patientHistoryRepository.findById(id).get();
    }

    public void save(PatientHistory patientHistory) {
        patientHistoryRepository.save(patientHistory);
    }

    public void updatePatientHistory(String temperature, String bloodPressure, boolean liver, boolean diabetes, boolean rheumatism, boolean nerve, boolean allergy, boolean digest, boolean respiratory, boolean cardiovascular, boolean kidney, String other1, boolean temporomandibularJoint, boolean toothExtraction, boolean orthodonticTreatment, boolean dentalBraces, String other2, Date date, String note, int appointmentId) {
        patientHistoryRepository.updatePatientHistory(temperature, bloodPressure, liver, diabetes, rheumatism, nerve, allergy, digest, respiratory, cardiovascular, kidney, other1, temporomandibularJoint, toothExtraction, orthodonticTreatment, dentalBraces, other2, date, note, appointmentId);
    }

    public void delete(int id) {
        patientHistoryRepository.deleteById(id);
    }
}
