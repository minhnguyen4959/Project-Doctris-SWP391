package com.dental.service;

import com.dental.entity.Doctor;
import com.dental.repository.DoctorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.util.List;

@Service
public class DoctorService  {
    @Autowired
    DoctorRepository doctorRepository;

    public List<Doctor> getAll() {
        return doctorRepository.findAll();
    }

    public Doctor get(int id) {
        return doctorRepository.findById(id).get();
    }

    public void save(Doctor blog) {
        doctorRepository.save(blog);
    }

    public void updateDoctor(String description, int id) {
        doctorRepository.setDoctorInfoById(description, id);
    }

    public void delete(int id) {
        doctorRepository.deleteById(id);
    }

    public Page<Doctor> findAll(Pageable pageable) {
        return doctorRepository.findAll(pageable);
    }

    public Page<Doctor> findAllByUserStatusAndUserFullNameAndUserGender(boolean status ,String fullName, String gender, Pageable pageable) {
        return doctorRepository.findAllByUserStatusAndUserFullNameContainingAndUserGender(status, fullName, gender, pageable);
    }

    public Page<Doctor> findAllByUserStatusAndUserFullName(boolean status ,String fullName, Pageable pageable) {
        return doctorRepository.findAllByUserStatusAndUserFullNameContaining(status, fullName, pageable);
    }

    public Page<Doctor> findAllByUserStatusAndUserGender(boolean status ,String gender, Pageable pageable) {
        return doctorRepository.findAllByUserStatusAndUserGender(status, gender, pageable);
    }

    public Page<Doctor> findAllByUserFullNameAndUserGender(String fullName ,String gender, Pageable pageable) {
        return doctorRepository.findAllByUserFullNameContainingAndUserGender(fullName, gender, pageable);
    }

    public Page<Doctor> findAllByUserFullName(String fullName, Pageable pageable) {
        return doctorRepository.findAllByUserFullNameContaining(fullName, pageable);
    }

    public Page<Doctor> findAllByUserStatus(boolean status, Pageable pageable) {
        return doctorRepository.findAllByUserStatus(status, pageable);
    }

    public Page<Doctor> findAllByUserGender(String gender, Pageable pageable) {
        return doctorRepository.findAllByUserGender(gender, pageable);
    }

    // User Page
    public Page<Doctor> findAllByUserStatusTrue(Pageable pageable) {
        return doctorRepository.findAllByUserStatusTrue(pageable);
    }

    public Page<Doctor> findAllByUserFullNameAndUserStatusTrue(String fullName, Pageable pageable) {
        return doctorRepository.findAllByUserFullNameContainingAndUserStatusTrue(fullName, pageable);
    }

    public List<Doctor> getAllDoctorEmptyCalendar(Date date, String time){
        return doctorRepository.getAllDoctorEmptyCalendar(date, time);
    }

    public long countDoctors() {
        return doctorRepository.count();
    }

    public int countDoctorsByUserStatus() {
        return doctorRepository.countDoctorsByUserStatus(true);
    }
}
