package com.dental.service;

import com.dental.entity.Appointment;
import com.dental.repository.AppointmentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class AppointmentService {

    @Autowired
    AppointmentRepository appointmentRepository;

    public List<Appointment> getAll() {
        return appointmentRepository.findAll();
    }

    public Appointment get(int id) {
        return appointmentRepository.findById(id).get();
    }
    public Optional<Appointment> getById(int id) {
        return appointmentRepository.findById(id);
    }

//    public Page<Appointment> getAllByBlogId(int blogId, Pageable pageable) {
//        return appointmentRepository.findAllByBlogBlogId(blogId, pageable);
//    }

    public void save(Appointment appointment) {
        appointmentRepository.save(appointment);
    }

    public void delete(int id) {
        appointmentRepository.deleteById(id);
    }

    public void updateAppointmentStatus(String status, int id) {
        appointmentRepository.updateAppointmentStatus(status, id);
    }

    public void cancelAppointment(int id) {
        appointmentRepository.cancelAppointment("Cancel", id);
    }

    public void updateAppointmentDoctor(int doctorId, int appointmentId){
        appointmentRepository.updateAppointmentDoctor(doctorId, appointmentId);
    }

    public Page<Appointment> findAllByOrderByDateDesc(Pageable pageable) {
        return appointmentRepository.findAllByOrderByDateDesc(pageable);
    }

    public Page<Appointment> findAllByDate(Date date, Pageable pageable) {
        return appointmentRepository.findAllByDate(date, pageable);
    }

    public Page<Appointment> findAllByStatus(String status, Pageable pageable) {
        return appointmentRepository.findAllByStatus(status, pageable);
    }

    public Page<Appointment> findAllByStatusAndDate(String status, Date date, Pageable pageable) {
        return appointmentRepository.findAllByStatusAndDate(status, date, pageable);
    }

    public Page<Appointment> findAllByPatientPatientIdOrderByDateDesc(int patientId, Pageable pageable) {
        return appointmentRepository.findAllByPatientPatientIdOrderByDateDesc(patientId, pageable);
    }

    public Page<Appointment> findAllByPatientPatientIdAndStatus(int patientId, String status, Pageable pageable) {
        return appointmentRepository.findAllByPatientPatientIdAndStatus(patientId, status, pageable);
    }

    public Page<Appointment> findAllByPatientPatientIdAndDate(int patientId, Date date, Pageable pageable) {
        return appointmentRepository.findAllByPatientPatientIdAndDate(patientId, date, pageable);
    }

    public Page<Appointment> findAllByPatientPatientIdAndStatusAndDate(int patientId, String status, Date date, Pageable pageable) {
        return appointmentRepository.findAllByPatientPatientIdAndStatusAndDate(patientId, status, date, pageable);
    }

    public Page<Appointment> findAllByDoctorDoctorIdOrderByDateDesc(int patientId, Pageable pageable) {
        return appointmentRepository.findAllByDoctorDoctorIdOrderByDateDesc(patientId, pageable);
    }

    public Page<Appointment> findAllByDoctorDoctorIdAndStatus(int doctorId, String status, Pageable pageable) {
        return appointmentRepository.findAllByDoctorDoctorIdAndStatus(doctorId, status, pageable);
    }

    public Page<Appointment> findAllByDoctorDoctorIdAndDate(int doctorId, Date date, Pageable pageable) {
        return appointmentRepository.findAllByDoctorDoctorIdAndDate(doctorId, date, pageable);
    }

    public Page<Appointment> findAllByDoctorDoctorIdAndStatusAndDate(int doctorId, String status, Date date, Pageable pageable) {
        return appointmentRepository.findAllByDoctorDoctorIdAndStatusAndDate(doctorId, status, date, pageable);
    }

    public int countAppointmentsByDate(Date date) {
        return appointmentRepository.countAppointmentsByDate(date);
    }

    public int countAppointmentsByDateAndTime(Date date, String time) {
        return appointmentRepository.countAppointmentsByDateAndTime(date, time);
    }

    public List<Double> getTotalBill(int appointmentId){
        return appointmentRepository.getTotalBill(appointmentId);
    }

    public Page<Appointment> findAllByPatientUserFullName(String fullname, Pageable pageable) {
        return appointmentRepository.findAllByPatientUserFullNameContaining(fullname, pageable);
    }

    public Page<Appointment> findAllByStatusAndPatientUserFullName(String status,String fullname, Pageable pageable) {
        return appointmentRepository.findAllByStatusAndPatientUserFullNameContaining(status,fullname, pageable);
    }

    public Page<Appointment> findAllByDateAndPatientUserFullName(Date date, String fullname, Pageable pageable) {
        return appointmentRepository.findAllByDateAndPatientUserFullNameContaining(date, fullname, pageable);
    }

    public Page<Appointment> findAllByStatusAndDateAndPatientUserFullName(String status, Date date, String fullname, Pageable pageable) {
        return appointmentRepository.findAllByStatusAndDateAndPatientUserFullNameContaining(status, date, fullname, pageable);
    }

    public int findCountByPatientIdAndServiceId(int patientId, int serviceId) {
        return appointmentRepository.findCountByPatientIdAndServiceId(patientId, serviceId);
    }

    public int countAllPatientBooking(){
        return appointmentRepository.countAllPatientBooking();
    }

//
    public Double getTotalRevenue(){
        double total = 0;
        List<Appointment> appointments = appointmentRepository.findAllByStatus("Completed");
        for (Appointment a: appointments
             ) {
            total += appointmentRepository.getTotalBill(a.getAppointmentId()).get(0);
        }
        return total;
    }

    public int countAppointments(){
        return appointmentRepository.countAppointments();
    }

//    List<Appointment> getAppointmentsByMonth(int month){
//        return appointmentRepository.getAppointmentsByMonth(month);
//    }

    public Double getRevenueByMonth(int year, int month){
        double total = 0;
        List<Appointment> appointments = appointmentRepository.findByDateYearAndDateMonthAndStatus(year, month);

        for (Appointment a: appointments
             ) {
            total += appointmentRepository.getTotalBill(a.getAppointmentId()).get(0);
        }

        return total;
    }

    public Double getRevenueByDay(int day){
        LocalDate currentDate = LocalDate.now();
        int year = currentDate.getYear();
        int month = currentDate.getMonthValue();
        double total = 0;
        List<Appointment> appointments = appointmentRepository.findByDateYearAndDateMonthAndDateDayAndStatus(year, month, day);

        for (Appointment a: appointments
        ) {
            total += appointmentRepository.getTotalBill(a.getAppointmentId()).get(0);
        }

        return total;
    }

    public int countAppointmentByMonth(int year, int month){
        return appointmentRepository.countAppointmentByMonth(year, month);
    }

    public int countAppointmentByDay(int day){
        LocalDate currentDate = LocalDate.now();
        int year = currentDate.getYear();
        int month = currentDate.getMonthValue();
        return appointmentRepository.countByDateDay(year, month, day);
    }
}
