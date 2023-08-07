package com.dental.repository;

import com.dental.entity.Appointment;
import com.dental.entity.Doctor;
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
public interface AppointmentRepository extends JpaRepository<Appointment, Integer> {
    Page<Appointment> findAllByOrderByDateDesc(Pageable pageable);

    Page<Appointment> findAllByDate(Date date, Pageable pageable);

    Page<Appointment> findAllByStatus(String status, Pageable pageable);

    Page<Appointment> findAllByStatusAndDate(String status, Date date, Pageable pageable);

    Page<Appointment> findAllByPatientPatientIdOrderByDateDesc(int patientId, Pageable pageable);

    Page<Appointment> findAllByPatientPatientIdAndDate(int patientId, Date date, Pageable pageable);

    Page<Appointment> findAllByPatientPatientIdAndStatus(int patientId, String status, Pageable pageable);

    Page<Appointment> findAllByPatientPatientIdAndStatusAndDate(int patientId, String status, Date date, Pageable pageable);

    Page<Appointment> findAllByDoctorDoctorIdOrderByDateDesc(int patientId, Pageable pageable);

    Page<Appointment> findAllByDoctorDoctorIdAndDate(int patientId, Date date, Pageable pageable);

    Page<Appointment> findAllByDoctorDoctorIdAndStatus(int patientId, String status, Pageable pageable);

    Page<Appointment> findAllByDoctorDoctorIdAndStatusAndDate(int patientId, String status, Date date, Pageable pageable);

    Page<Appointment> findAllByPatientUserFullNameContaining(String fullname, Pageable pageable);

    Page<Appointment> findAllByStatusAndPatientUserFullNameContaining(String status, String fullname, Pageable pageable);

    Page<Appointment> findAllByDateAndPatientUserFullNameContaining(Date date, String fullname, Pageable pageable);

    Page<Appointment> findAllByStatusAndDateAndPatientUserFullNameContaining(String status, Date date, String fullname, Pageable pageable);

    @Transactional
    @Modifying
    @Query(value = "UPDATE appointment p SET p.status = ?1, p.doctor_id = null WHERE p.appointment_id = ?2", nativeQuery = true)
    void cancelAppointment(String status, int appointmentId);

    @Transactional
    @Modifying
    @Query(value = "UPDATE appointment p SET p.status = ?1 WHERE p.appointment_id = ?2", nativeQuery = true)
    void updateAppointmentStatus(String status, int appointmentId);

    @Transactional
    @Modifying
    @Query(value = "UPDATE `clinic_dental`.`appointment` SET `doctor_id` = ? WHERE (`appointment_id` = ?)", nativeQuery = true)
    void updateAppointmentDoctor(int doctorId, int appointmentId);

    int countAppointmentsByDate(Date date);

    int countAppointmentsByDateAndTime(Date date, String time);

    @Transactional
    @Query(value = "SELECT SUM(service.price) AS total_price " +
            "FROM appointment " +
            "JOIN appointment_detail ON appointment.appointment_id = appointment_detail.appointment_id " +
            "JOIN service ON appointment_detail.service_id = service.service_id " +
            "GROUP BY appointment.appointment_id " +
            "HAVING appointment_id = ?", nativeQuery = true)
    List<Double> getTotalBill(int appointmentId);

    @Query("SELECT COUNT(s.serviceId) " +
            "FROM Appointment a " +
            "JOIN a.service s " +
            "WHERE a.patient.patientId = ?1 " +
            "AND s.serviceId = ?2 " +
            "GROUP BY a.patient.patientId, s.serviceId")
    int findCountByPatientIdAndServiceId(int patientId, int serviceId);
    @Query("SELECT COUNT(DISTINCT a.patient.patientId) AS patient_count\n" +
            "FROM Appointment a")
    int countAllPatientBooking();

    List<Appointment> findAllByStatus(String status);

    @Query("SELECT COUNT(a) FROM Appointment a")
    int countAppointments();

    @Query("SELECT a FROM Appointment a WHERE YEAR(a.date) = :year AND MONTH(a.date) = :month AND a.status = 'Completed'")
    List<Appointment> findByDateYearAndDateMonthAndStatus(int year, int month);

    @Query("SELECT a FROM Appointment a WHERE YEAR(a.date) = :year AND MONTH(a.date) = :month AND DAY(a.date) = :day AND a.status = 'Completed'")
    List<Appointment> findByDateYearAndDateMonthAndDateDayAndStatus(int year, int month, int day);

    @Query("SELECT COUNT(a) FROM Appointment a WHERE YEAR(a.date) = :year AND MONTH(a.date) = :month")
    int countAppointmentByMonth(int year, int month);

    @Query("SELECT COUNT(a) FROM Appointment a WHERE YEAR(a.date) = :year AND MONTH(a.date) = :month AND DAY(a.date) = :day ")
    int countByDateDay(int year, int month, int day);

}
