package com.dental.controller;

import com.dental.entity.*;
import com.dental.service.*;
import com.dental.util.Const;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.sql.Date;
import java.sql.SQLOutput;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Controller
@RequestMapping()
public class AppointmentController {

    @Autowired
    AppointmentService appointmentService;

    @Autowired
    PatientService patientService;

    @Autowired
    UserService userService;

    @Autowired
    SService serviceService;

    @Autowired
    RateStarService rateStarService;

    @Autowired
    DoctorService doctorService;

    @GetMapping("/booking")
    public String formAppointment(
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @RequestParam(value = "serviceId", required = false) List<Integer> serviceIds,
            Model model
    ) {
        if (userDetails == null) {
            return "redirect:/";
        }
        if (serviceIds == null) {
            serviceIds = new ArrayList<>();
        }

        model.addAttribute("appointment", new Appointment());
        model.addAttribute("user", new User());
        model.addAttribute("services", serviceService.getAll());
        model.addAttribute("selectedServices", serviceIds);
        return "landing/appointment/booking";
    }

    @GetMapping("/appointments")
    public String listAppointment(
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            Model model,
            @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
            @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR) Integer pageSize,
            @RequestParam(name = "date", required = false) Date date,
            @RequestParam(name = "status", required = false) String status
    ) {
        if (userDetails == null) {
            return "redirect:/";
        }

        if (pageNum < 1) {
            pageNum = 1;
        }

        String role = userDetails.getUserEntity().getRole();
        int userId = userDetails.getUserEntity().getUserId();
        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        Page<Appointment> appointments;

        if (role.equals("Patient")) {
            if (date != null && status != null && !status.isEmpty()) {
                appointments = appointmentService.findAllByPatientPatientIdAndStatusAndDate(userId, status, date, pageable);
            } else if (status != null && !status.isEmpty()) {
                appointments = appointmentService.findAllByPatientPatientIdAndStatus(userId, status, pageable);
            } else if (date != null) {
                appointments = appointmentService.findAllByPatientPatientIdAndDate(userId, date, pageable);
            } else {
                appointments = appointmentService.findAllByPatientPatientIdOrderByDateDesc(userId, pageable);
            }
        } else {
            if (date != null && status != null && !status.isEmpty()) {
                appointments = appointmentService.findAllByDoctorDoctorIdAndStatusAndDate(userId, status, date, pageable);
            } else if (status != null && !status.isEmpty()) {
                appointments = appointmentService.findAllByDoctorDoctorIdAndStatus(userId, status, pageable);
            } else if (date != null) {
                appointments = appointmentService.findAllByDoctorDoctorIdAndDate(userId, date, pageable);
            } else {
                appointments = appointmentService.findAllByDoctorDoctorIdOrderByDateDesc(userId, pageable);
            }
        }

        model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
        model.addAttribute("appointments", appointments);
        model.addAttribute("status", status);
        model.addAttribute("date", date);
        model.addAttribute("numberOfPage", appointments.getTotalPages());
        return "landing/appointment/appointments";
    }

    @GetMapping("/appointment/{appointmentId}")
    public String appointmentDetail(
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
        List<Service> services = appointment.getService();
        double totalPrice = 0;
        for (Service s : services) {
            totalPrice += Double.parseDouble(s.getPrice());
        }

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
        model.addAttribute("appointment", appointment);
        model.addAttribute("rateStar", new RateStar());
        model.addAttribute("totalPrice", totalPrice);
        return "landing/appointment/appointment-detail";
    }

    @PostMapping("/booking/save")
    public String makeAppointment(
            @Valid Appointment appointment,
            BindingResult result,
            @Valid User user,
            BindingResult userResult,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @RequestParam(value = "services", required = false) List<Integer> serviceIds
    ) {
        if (userDetails == null) {
            return "redirect:/";
        }

        String role = userDetails.getUserEntity().getRole();
        boolean hasErr = false;

        if (!role.equals("Patient")) {
            hasErr = true;
            model.addAttribute("errMes", "Only patient can make appointment");
        }

        if (serviceIds == null) {
            hasErr = true;
            model.addAttribute("service", "Please choose at least 1 service");
        }

        if (serviceIds != null && serviceIds.size() > 3) {
            hasErr = true;
            model.addAttribute("service", "Please choose max 3 services");
        }

        if (result.hasErrors() || userResult.hasFieldErrors("phoneNumber") || hasErr) {
            model.addAttribute("services", serviceService.getAll());
            model.addAttribute("selectedServices", serviceIds);
            return "landing/appointment/booking";
        }

        LocalDate currentDate = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate comparisonDate = LocalDate.parse(appointment.getDateString(), formatter);

        if (comparisonDate.equals(currentDate)) {
            ZoneId zone = ZoneId.of("Asia/Ho_Chi_Minh");
            LocalTime currentTime = LocalTime.now(zone);
            DateTimeFormatter formatter2 = DateTimeFormatter.ofPattern("HH");
            String hour24Format = currentTime.format(formatter2);

            if (appointment.getTime().equals("Morning") && Integer.parseInt(hour24Format) >= 9) {
                model.addAttribute("services", serviceService.getAll());
                model.addAttribute("selectedServices", serviceIds);
                model.addAttribute("time", "Booking time for this morning is over");
                return "landing/appointment/booking";
            }

            if (appointment.getTime().equals("Afternoon") && Integer.parseInt(hour24Format) >= 15) {
                model.addAttribute("services", serviceService.getAll());
                model.addAttribute("selectedServices", serviceIds);
                model.addAttribute("time", "Booking time for this day is over");
                return "landing/appointment/booking";
            }
        }

        long numOfDoctors = doctorService.countDoctorsByUserStatus();
        int numOfAppointment = appointmentService.countAppointmentsByDateAndTime(appointment.getDate(), appointment.getTime());
        if (numOfAppointment >= numOfDoctors * 5) {
            model.addAttribute("errMes", "This slot is full. You can book another slot or day!");
            model.addAttribute("services", serviceService.getAll());
            model.addAttribute("selectedServices", serviceIds);
            return "landing/appointment/booking";
        }
        List<Service> selectedServices = serviceService.getAllByIds(serviceIds);
        int patientId = userDetails.getUserEntity().getUserId();
        Patient patient = patientService.get(patientId);
        appointment.setPatient(patient);
        appointment.setStatus("New");
        appointment.setService(selectedServices);

        try {
            appointmentService.save(appointment);
            return "redirect:/appointments";
        } catch (Error e) {
            return "landing/appointment/booking";
        }
    }

    @PostMapping("/appointments/delete/{appointmentId}")
    public String cancelAppointment(@PathVariable("appointmentId") int appointmentId, Model model) throws IllegalAccessException {
        try {
            Appointment p = appointmentService.get(appointmentId);
            if (p != null && p.getStatus().equals("Completed")) {
                throw new IllegalAccessException("Cannot cancel this appointment!");
            }

            if (p.getStatus().equals("Cancel")) {
                throw new IllegalAccessException("Cannot cancel this appointment!");
            }

            appointmentService.cancelAppointment(appointmentId);
        } catch (Error e) {
            throw new IllegalAccessException("Failed to cancel!");
        }
        return "redirect:/appointments";
    }

    @PostMapping("/appoinment/completed/{appointmentId}")
    public String completeAppointment(@PathVariable("appointmentId") int appointmentId, Model model) throws IllegalAccessException {
        try {
            Appointment p = appointmentService.get(appointmentId);
            if (p != null && !p.getStatus().equals("Assigned")) {
                throw new IllegalAccessException("Cannot change this appointment to complete !");
            }

            appointmentService.updateAppointmentStatus("Completed", appointmentId);
        } catch (Error e) {
            throw new IllegalAccessException("Failed to change status!");
        }
        return "redirect:/appointment/" + appointmentId;
    }

    @GetMapping("/admin/appointments")
    public String viewListAppointment(Model model,
                                      @AuthenticationPrincipal UserDetailsImpl userDetails,
                                      @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
                                      @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR) Integer pageSize,
                                      @RequestParam(name = "fullName", required = false) String fullName,
                                      @RequestParam(name = "date", required = false) Date date,
                                      @RequestParam(name = "status", required = false) String status)
    {

        System.out.println("==============Test==========:" + "page=" + pageNum + "pageSize=" + pageSize + "date=" + date + "status=" + status + "fullName" + fullName);
        if (userDetails == null) {
            return "redirect:/";
        }

        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        Page<Appointment> appointments;
        appointments = appointments = appointmentService.findAllByOrderByDateDesc(pageable);

        List<Doctor> doctors = doctorService.getAll();



        if (fullName != null && !fullName.isEmpty() && status != null && !status.isEmpty() && date!= null){
            appointments = appointmentService.findAllByStatusAndDateAndPatientUserFullName(status, date, fullName, pageable);
        } else if (date != null && fullName != null && !fullName.isEmpty()) {
            appointments = appointmentService.findAllByDateAndPatientUserFullName( date, fullName, pageable);
        }else if(date != null && status != null && !status.isEmpty() ){
            appointments = appointmentService.findAllByStatusAndDate(status, date, pageable);
        }else if(fullName != null && !fullName.isEmpty() && status!=null && !status.isEmpty()){
            appointments = appointmentService.findAllByStatusAndPatientUserFullName(status, fullName, pageable);
        }else if(status != null && !status.isEmpty()){
            appointments = appointmentService.findAllByStatus(status, pageable);
        }else if(fullName !=null && !fullName.isEmpty()){
            appointments = appointmentService.findAllByPatientUserFullName(fullName, pageable);
        }else if(date != null){
            appointments = appointmentService.findAllByDate(date, pageable);
        }else{
            appointments = appointmentService.findAllByOrderByDateDesc(pageable);
        }


        model.addAttribute("appointments", appointments);
        model.addAttribute("doctors", doctors);
        model.addAttribute("status", status);
        model.addAttribute("date", date);
        model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
        model.addAttribute("numberOfPage", appointments.getTotalPages());
        model.addAttribute("fullName", fullName);

        return "admin/appointment/appointment";
    }


    @GetMapping("/admin/appointment/{appointmentId}")
    public String viewAppointmentDetails(
            @PathVariable("appointmentId") int appointmentId,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails
    ) {
        //
        if (userDetails == null) {
            return "redirect:/";
        }

        Optional<Appointment> a = appointmentService.getById(appointmentId);
        if (a == null || a.isEmpty()) {
            return "redirect:/admin/appointments";
        }
        Appointment appointment = a.get();

        List<Doctor> doctors = doctorService.getAllDoctorEmptyCalendar(appointment.getDate(), appointment.getTime());
        if (doctors.isEmpty()) {
            doctors = doctorService.getAll();
        }
        List<Double> total = appointmentService.getTotalBill(appointment.getAppointmentId());
        model.addAttribute("total", total.get(0));


        model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
        model.addAttribute("appointment", appointment);
        model.addAttribute("doctors", doctors);
        model.addAttribute("appointmentId", appointmentId);

        return "admin/appointment/appointment-detail";
    }

    @PostMapping("/admin/assign-appointment")
    public String assignDoctor(
            @RequestParam("doctorId") int doctorId,
            @RequestParam("appointmentId") int appointmentId,
            Model model,
            RedirectAttributes redirectAttributes
    ) {

        Doctor doctor = doctorService.get(doctorId);

        Optional<Appointment> a = appointmentService.getById(appointmentId);
        if (a == null || a.isEmpty()) {
            return "redirect:/admin/appointments";
        }
        Appointment appointment = a.get();
        System.out.println(appointment.getStatus());

        if (appointment.getStatus().equals("Cancel") || appointment.getStatus().equals("Completed")) {
            redirectAttributes.addFlashAttribute("errorMessage", "Can not assign");
            return "redirect:/admin/appointment/" + appointmentId;
        }


        LocalDate currentDate = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate comparisonDate = LocalDate.parse(appointment.getDateString(), formatter);

        System.out.println("comparisonDateTest="+comparisonDate.isBefore(currentDate));
        if (comparisonDate.isBefore(currentDate)) {
            redirectAttributes.addFlashAttribute("errorMessage", "Overtime to assign");
            return "redirect:/admin/appointment/" + appointmentId;
        }

        if (comparisonDate.equals(currentDate)) {
            ZoneId zone = ZoneId.of("Asia/Ho_Chi_Minh");
            LocalTime currentTime = LocalTime.now(zone);
            DateTimeFormatter formatter2 = DateTimeFormatter.ofPattern("HH");
            String hour24Format = currentTime.format(formatter2);

            if (appointment.getTime().equals("Morning") && Integer.parseInt(hour24Format) >= 12) {
                redirectAttributes.addFlashAttribute("errorMessage", "Overtime to assign");
                return "redirect:/admin/appointment/" + appointmentId;
            }

            if (appointment.getTime().equals("Afternoon") && Integer.parseInt(hour24Format) >= 18) {
                redirectAttributes.addFlashAttribute("errorMessage", "Overtime to assign");
                return "redirect:/admin/appointment/" + appointmentId;
            }
        }

        appointment.setDoctor(doctor);
        appointmentService.updateAppointmentDoctor(doctor.getDoctorId(), appointmentId);
        appointmentService.updateAppointmentStatus("Assigned", appointmentId);

        return "redirect:/admin/appointment/" + appointmentId;
    }

    @PostMapping("/admin/appointments/delete/{appointmentId}")
    public String deleteAppointment(@PathVariable("appointmentId") int appointmentId, Model model) throws IllegalAccessException {
        try {
            Appointment p = appointmentService.get(appointmentId);
            if (p != null && p.getStatus().equals("Completed")) {
                throw new IllegalAccessException("Cannot cancel this appointment!");
            }

            if (p.getStatus().equals("Cancel")) {
                throw new IllegalAccessException("Cannot cancel this appointment!");
            }

            appointmentService.cancelAppointment(appointmentId);
        } catch (Error e) {
            throw new IllegalAccessException("Failed to cancel!");
        }

        return "redirect:/admin/appointments";
    }

    @PostMapping("/feedback/save")
    public String feedback(
            @RequestParam("serviceId") int serviceId,
            @RequestParam("star") int star,
            @RequestParam("feedback") String feedback,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails
    ) throws Exception {
        int userId = userDetails.getUserEntity().getUserId();
        String role = userDetails.getUserEntity().getRole();

        if (!role.equals("Patient")) {
            throw new IllegalAccessException("You cannot send feedback");
        }

        int count = appointmentService.findCountByPatientIdAndServiceId(userId, serviceId);
        int countS = rateStarService.countAllByUserUserIdAndServiceServiceId(userId, serviceId);

        if (countS >= count) {
            throw new Exception("You just can feedback 1 times/service");
        }

        RateStar rateStar = new RateStar(star, feedback, userDetails.getUserEntity(), serviceService.get(serviceId));

        rateStarService.saveRateStar(rateStar);
        return "redirect:/service/" + serviceId;
    }
}
