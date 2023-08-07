package com.dental.controller;

import com.dental.entity.Appointment;
import com.dental.entity.PatientHistory;
import com.dental.entity.User;
import com.dental.entity.UserDetailsImpl;
import com.dental.service.*;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.sql.Date;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping()
public class PatientHistoryController {

    @Autowired
    AppointmentService appointmentService;

    @Autowired
    PatientService patientService;

    @Autowired
    UserService userService;

    @Autowired
    SService serviceService;

    @Autowired
    DoctorService doctorService;

    @Autowired
    PatientHistoryService patientHistoryService;

    @GetMapping("/appointment/medical/{appointmentId}")
    public String addMedical(
            @PathVariable("appointmentId") int appointmentId,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails
    ) {
        if (userDetails == null) {
            return "redirect:/";
        }

        String role = userDetails.getUserEntity().getRole();
        int userId = userDetails.getUserEntity().getUserId();
        Optional<Appointment> a = appointmentService.getById(appointmentId);

        if (a == null || a.isEmpty()) {
            return "redirect:/appointments";
        }
        Appointment appointment = a.get();

        if (role.equals("Patient")) {
            if (appointment.getPatient().getPatientId() != userId) {
                return "redirect:/appointments";
            }
        } else {
            if (appointment.getDoctor() == null) {
                return "redirect:/appointments";
            }
            if (appointment.getDoctor().getDoctorId() != userId) {
                return "redirect:/appointments";
            }
        }

        model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
        model.addAttribute("patientHistory", new PatientHistory());
        model.addAttribute("appointment", appointment);
        return "landing/appointment/add-medical";
    }

    @PostMapping("/appointment/medical/{appointmentId}")
    public String saveMedical(
            @Valid PatientHistory patientHistory,
            BindingResult result,
            @Valid Appointment appointment,
            BindingResult appointmentResult,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @PathVariable("appointmentId") int appointmentId
    ) {
        patientHistory.setAppointment(appointmentService.get(appointmentId));
        if (userDetails == null) {
            return "redirect:/";
        }
        Optional<Appointment> a = appointmentService.getById(appointmentId);
        Appointment app = a.get();
        appointment.setAppointmentId(app.getAppointmentId());
        appointment.setPatient(app.getPatient());
        appointment.setStatus(app.getStatus());
        appointment.setNote(app.getNote());
        appointment.setTime(app.getTime());
        appointment.setDoctor(app.getDoctor());

        Date date = new Date(System.currentTimeMillis());
        patientHistory.setDate(date);
        if (date != appointment.getDate()) {
            model.addAttribute("error", "Can not create medical information in the past/future");
        }
        if (result.hasErrors() || appointmentResult.hasErrors()) {
            model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
            model.addAttribute("appointment", app);
            System.out.println("aaaaaaaaaaaaaaaaaaa");
            System.out.println(result.getAllErrors());
            System.out.println(appointmentResult.getAllErrors());
            return "landing/appointment/add-medical";
        }

        try {
            appointmentService.updateAppointmentStatus("Completed", appointmentId);
            patientHistoryService.save(patientHistory);
            return "redirect:/appointment/" + appointmentId;
        } catch (Error e) {
            return "landing/appointment/add-medical";
        }
    }

    @GetMapping("/appointment/medical/edit/{appointmentId}")
    public String editMedical(
            @PathVariable("appointmentId") int appointmentId,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails
    ) {
        if (userDetails == null) {
            return "redirect:/";
        }

        String role = userDetails.getUserEntity().getRole();
        int userId = userDetails.getUserEntity().getUserId();
        Optional<Appointment> a = appointmentService.getById(appointmentId);

        if (a == null || a.isEmpty()) {
            return "redirect:/appointments";
        }
        Appointment appointment = a.get();

        if (role.equals("Patient")) {
            if (appointment.getPatient().getPatientId() != userId) {
                return "redirect:/appointments";
            }
        } else {
            if (appointment.getDoctor() == null) {
                return "redirect:/appointments";
            }
            if (appointment.getDoctor().getDoctorId() != userId) {
                return "redirect:/appointments";
            }
        }

        model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
        model.addAttribute("patientHistory", patientHistoryService.get(appointmentId));
        model.addAttribute("appointment", appointment);
        return "landing/appointment/update-medical";
    }

    @PostMapping("/appointment/medical/update/{appointmentId}")
    public String updateMedical(
            @Valid PatientHistory patientHistory,
            BindingResult result,
            @Valid Appointment appointment,
            BindingResult appointmentResult,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @PathVariable("appointmentId") int appointmentId
    ) {
        patientHistory.setAppointment(appointmentService.get(appointmentId));
        if (userDetails == null) {
            return "redirect:/";
        }
        Optional<Appointment> a = appointmentService.getById(appointmentId);
        Appointment app = a.get();
        appointment.setAppointmentId(app.getAppointmentId());
        appointment.setPatient(app.getPatient());
        appointment.setStatus(app.getStatus());
        appointment.setNote(app.getNote());
        appointment.setTime(app.getTime());
        appointment.setDoctor(app.getDoctor());

        Date date = new Date(System.currentTimeMillis());

        System.out.println(date);
        System.out.println(appointment.getDate());
        if (date != appointment.getDate()) {
            model.addAttribute("error", "Can not update medical information in the past/future");
        }
        patientHistory.setDate(date);
        if (result.hasErrors() || appointmentResult.hasErrors()) {
            model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
            model.addAttribute("appointment", app);
            System.out.println(result.getAllErrors());
            System.out.println(appointmentResult.getAllErrors());
            return "landing/appointment/update-medical";
        }

        String temperature = patientHistory.getTemperature();
        String bloodPressure = patientHistory.getBloodPressure();
        boolean liver = patientHistory.isLiver();
        boolean diabetes = patientHistory.isDiabetes();
        boolean rheumatism = patientHistory.isRheumatism();
        boolean nerve = patientHistory.isNerve();
        boolean allergy = patientHistory.isAllergy();
        boolean digest = patientHistory.isDigest();
        boolean respiratory = patientHistory.isRespiratory();
        boolean cardiovascular = patientHistory.isCardiovascular();
        boolean kidney = patientHistory.isKidney();
        String other1 = patientHistory.getOther1();
        boolean temporomandibularJoint = patientHistory.isTemporomandibularJoint();
        boolean toothExtraction = patientHistory.isToothExtraction();
        boolean orthodonticTreatment = patientHistory.isOrthodonticTreatment();
        boolean dentalBraces = patientHistory.isDentalBraces();
        String other2 = patientHistory.getOther2();
//        Date date = patientHistory.getDate();
        String note = patientHistory.getNote();

        try {
            appointmentService.updateAppointmentStatus("Completed", appointmentId);
            patientHistoryService.updatePatientHistory(temperature, bloodPressure, liver, diabetes, rheumatism, nerve, allergy, digest, respiratory, cardiovascular, kidney, other1, temporomandibularJoint, toothExtraction, orthodonticTreatment, dentalBraces, other2, date, note, appointmentId);
            return "redirect:/appointment/" + appointmentId;
        } catch (Error e) {
            return "landing/appointment/update-medical";
        }
    }
}
