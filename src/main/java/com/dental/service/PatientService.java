package com.dental.service;

import com.dental.entity.Blog;
import com.dental.entity.Patient;
import com.dental.repository.PatientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public class PatientService {
    @Autowired
    PatientRepository patientRepository;

    public List<Patient> getAll() {
        return patientRepository.findAll();
    }

    public Patient get(int id) {
        return patientRepository.findById(id).get();
    }

    public Patient getPatientById(int id) {
        return patientRepository.findById(id).get();
    }

    public void save(Patient blog) {
        patientRepository.save(blog);
    }

    public void updatePatient(String bloodGroup, int id) {

        patientRepository.setPatientInfoById(bloodGroup, id);
    }

    public void delete(int id) {
        patientRepository.deleteById(id);
    }

    public Page<Patient> findAll(Pageable pageable) {
        return patientRepository.findAll(pageable);
    }

    public Page<Patient> findAllByUserStatusAndUserFullNameAndUserGender(boolean status ,String fullName, String gender, Pageable pageable) {
        return patientRepository.findAllByUserStatusAndUserFullNameContainingAndUserGender(status, fullName, gender, pageable);
    }

    public Page<Patient> findAllByUserStatusAndUserFullName(boolean status ,String fullName, Pageable pageable) {
        return patientRepository.findAllByUserStatusAndUserFullNameContaining(status, fullName, pageable);
    }

    public Page<Patient> findAllByUserStatusAndUserGender(boolean status ,String gender, Pageable pageable) {
        return patientRepository.findAllByUserStatusAndUserGender(status, gender, pageable);
    }

    public Page<Patient> findAllByUserFullNameAndUserGender(String fullName ,String gender, Pageable pageable) {
        return patientRepository.findAllByUserFullNameContainingAndUserGender(fullName, gender, pageable);
    }

    public Page<Patient> findAllByUserFullName(String fullName, Pageable pageable) {
        return patientRepository.findAllByUserFullNameContaining(fullName, pageable);
    }

    public Page<Patient> findAllByUserStatus(boolean status, Pageable pageable) {
        return patientRepository.findAllByUserStatus(status, pageable);
    }

    public Page<Patient> findAllByUserGender(String gender, Pageable pageable) {
        return patientRepository.findAllByUserGender(gender, pageable);
    }

    // User Page
    public Page<Patient> findAllByUserStatusTrue(Pageable pageable) {
        return patientRepository.findAllByUserStatusTrue(pageable);
    }

    public Page<Patient> findAllByUserFullNameAndUserStatusTrue(String fullName, Pageable pageable) {
        return patientRepository.findAllByUserFullNameContainingAndUserStatusTrue(fullName, pageable);
    }
}
