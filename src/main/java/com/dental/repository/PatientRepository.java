package com.dental.repository;

import com.dental.entity.Patient;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface PatientRepository extends JpaRepository<Patient, Integer> {
    Page<Patient> findAll(Pageable pageable);

    Page<Patient> findAllByUserStatusAndUserFullNameContainingAndUserGender(boolean status, String name, String gender, Pageable pageable);

    Page<Patient> findAllByUserStatusAndUserFullNameContaining(boolean status, String name, Pageable pageable);

    Page<Patient> findAllByUserStatusAndUserGender(boolean status, String gender, Pageable pageable);

    Page<Patient> findAllByUserFullNameContainingAndUserGender(String fullName, String gender, Pageable pageable);

    Page<Patient> findAllByUserFullNameContaining(String fullName, Pageable pageable);

    Page<Patient> findAllByUserStatus(boolean status, Pageable pageable);

    Page<Patient> findAllByUserGender(String gender, Pageable pageable);

    @Transactional
    @Modifying
    @Query(value = "UPDATE patient d SET d.blood_group = ?1 WHERE d.patient_id = ?2", nativeQuery = true)
    void setPatientInfoById(String bloodGroup, int userId);

    // User Page
    Page<Patient> findAllByUserStatusTrue(Pageable pageable);

    Page<Patient> findAllByUserFullNameContainingAndUserStatusTrue(String fullName, Pageable pageable);
}
