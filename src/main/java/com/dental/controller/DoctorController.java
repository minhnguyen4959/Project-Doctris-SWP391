package com.dental.controller;

import com.dental.entity.Doctor;
import com.dental.entity.User;
import com.dental.service.DoctorService;
import com.dental.service.UserService;
import com.dental.util.Const;
import com.dental.util.UploadFile;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDate;
import java.time.Period;
import java.util.List;

@Controller
@RequestMapping()
public class DoctorController {

    @Autowired
    DoctorService doctorService;

    @Autowired
    UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("admin/doctor")
    public String getAll(
            Model model,
            @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
            @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR) Integer pageSize,
            @RequestParam(name = "fullName", required = false) String fullName,
            @RequestParam(name = "statusSearch", required = false) String statusSearch,
            @RequestParam(name = "gender", required = false) String gender
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        List<Doctor> doctors = doctorService.getAll();
        Page<Doctor> Doctor;

        boolean status = true;
        if (statusSearch != null && statusSearch.equals("0")) {
            status = false;
        }

        if (fullName != null && !fullName.isEmpty() && statusSearch != null && !statusSearch.isEmpty() && gender != null && !gender.isEmpty()){
            Doctor = doctorService.findAllByUserStatusAndUserFullNameAndUserGender(status, fullName, gender, pageable);
        } else if (gender != null && !gender.isEmpty() && fullName != null && !fullName.isEmpty()){
            Doctor = doctorService.findAllByUserFullNameAndUserGender(fullName, gender, pageable);
        } else if (gender != null && !gender.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
            Doctor = doctorService.findAllByUserStatusAndUserGender(status, gender, pageable);
        } else if (fullName != null && !fullName.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
            Doctor = doctorService.findAllByUserStatusAndUserFullName(status, fullName, pageable);
        } else if (statusSearch != null && !statusSearch.isEmpty()) {
            Doctor = doctorService.findAllByUserStatus(status, pageable);
        } else if (fullName != null && !fullName.isEmpty()) {
            Doctor = doctorService.findAllByUserFullName(fullName, pageable);
        } else if (gender != null && !gender.isEmpty()) {
            Doctor = doctorService.findAllByUserGender(gender, pageable);
        } else {
            Doctor = doctorService.findAll(pageable);
        }

        model.addAttribute("fullName", fullName);
        model.addAttribute("statusSearch", statusSearch);
        model.addAttribute("usesPage", Doctor);
        model.addAttribute("numberOfPage", Doctor.getTotalPages());
        model.addAttribute("doctors", doctors);

        return "admin/doctor/doctors";
    }

    @GetMapping("admin/doctor/{doctorId}")
    public String getOne(@PathVariable("doctorId") int doctorId, Model model) {
        Doctor doctor = doctorService.get(doctorId);
        List<Doctor> doctors = doctorService.getAll();
        model.addAttribute("doctor", doctor);
        model.addAttribute("doctors", doctors);

        return "admin/doctor/dr-profile";
    }

    @GetMapping("admin/doctor/doctor-add")
    public String addDoctorForm(Model model) {
        List<Doctor> doctors = doctorService.getAll();
        model.addAttribute("user", new User());
        model.addAttribute("doctor", new Doctor());
        model.addAttribute("doctors", doctors);

        return "admin/doctor/add-doctor";
    }

    @PostMapping("admin/doctor/save")
    public String createDoctor(
            @Valid Doctor doctor, BindingResult doctorBindingResult,
            @Valid User user, BindingResult userBindingResult,
            @RequestParam("image") MultipartFile multipartFile, Model model
    ) {
        User u = userService.getByEmail(user.getEmail());
        boolean hasErr = false;

        if (u != null) {
            model.addAttribute("email", "Email already used");
        }

        if (multipartFile.isEmpty()) {
            model.addAttribute("image", "Avatar must be mandatory");
        }

        if (user.getDateOfBirth() == null) {
            hasErr = true;
            model.addAttribute("dateOfBirth", "Date of birth must be mandatory");
        } else {
            LocalDate birthDate = user.getDateOfBirth().toLocalDate();
            LocalDate currentDate = LocalDate.now();
            Period age = Period.between(birthDate, currentDate);

            if (age.getYears() < 20) {
                hasErr = true;
                model.addAttribute("dateOfBirth", "Your age must be greater than 20");
            }
        }

        if (user.getGender() == null) {
            model.addAttribute("gender", "Gender must be mandatory");
        }

        if (doctorBindingResult.hasErrors() || userBindingResult.hasErrors() || multipartFile.isEmpty() || u != null || hasErr) {
            List<Doctor> doctors = doctorService.getAll();
            model.addAttribute("doctors", doctors);
            return "admin/doctor/add-doctor";
        }

        user.setPassword(passwordEncoder.encode("minh123456789"));
        user.setRole("Doctor");

        try {
            String filename = UploadFile.saveFile(multipartFile);
            user.setAvatar(filename);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            userService.save(user);
            User u2 = userService.getByEmail(user.getEmail());
            doctor.setUser(u2);
            if (u2 != null) {
                doctorService.save(doctor);
            }

            return "redirect:/admin/doctor";
        } catch (Error e) {
            System.out.println(e);
            return "admin/doctor/add-doctor";
        }
    }

    @GetMapping("admin/doctor/edit/{doctorId}")
    public String editDoctor(@PathVariable("doctorId") int doctorId, Model model) {
        List<Doctor> doctors = doctorService.getAll();
        Doctor doctor = doctorService.get(doctorId);
        User user = userService.get(doctor.getUser().getUserId());
        model.addAttribute("doctor", doctor);
        model.addAttribute("user", user);
        model.addAttribute("doctors", doctors);
        return "admin/doctor/update-doctor";
    }

    @PostMapping("admin/doctor/update")
    public String updateDoctor(
            @Valid Doctor doctor, BindingResult doctorBindingResult,
            @Valid User user, BindingResult userBindingResult,
            Model model, @RequestParam(value = "image", required = false) MultipartFile multipartFile
    ) {
        int doctorId = user.getUserId();
        boolean hasErr = false;

        User u = userService.get(doctorId);
        user.setDoctor(u.getDoctor());

        user.setEmail(u.getEmail());
        user.setPassword(u.getPassword());
        user.setRole(u.getRole());
        user.setCreatedAt(u.getCreatedAt());

        if (user.getDateOfBirth() == null) {
            hasErr = true;
            model.addAttribute("dateOfBirth", "Date of birth must be mandatory");
        } else {
            LocalDate birthDate = user.getDateOfBirth().toLocalDate();
            LocalDate currentDate = LocalDate.now();
            Period age = Period.between(birthDate, currentDate);

            if (age.getYears() < 20) {
                hasErr = true;
                model.addAttribute("dateOfBirth", "Your age must be greater than 20");
            }
        }

        if (doctorBindingResult.hasErrors() || userBindingResult.hasErrors() || hasErr) {
            return "admin/doctor/update-doctor";
        }

        if (multipartFile != null) {
            String fileName = UploadFile.getFileName(multipartFile);

            if (!fileName.isEmpty()) {
                try {
                    String filename = UploadFile.saveFile(multipartFile);
                    user.setAvatar(filename);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        try {
            doctorService.updateDoctor(doctor.getDescription(), doctorId);
            userService.save(user);
            return "redirect:/admin/doctor/" + doctorId;
        } catch (Error e) {
            System.out.println(e);
            return "admin/doctor/update-doctor";
        }
    }

//    @PostMapping("admin/doctor/delete/{doctorId}")
//    public String deleteDoctor(@PathVariable("doctorId") int doctorId, Model model) throws IllegalAccessException {
//        try {
//            Doctor u = doctorService.get(doctorId);
//            doctorService.delete(doctorId);
//            userService.delete(u.getUser().getUserId());
//        } catch (Error e) {
//            throw new IllegalAccessException("Failed to delete!");
//        }
//        return "redirect:/admin/doctor";
//    }

    // USER PAGE
    @GetMapping("/doctor")
    public String getAllDoctor(
            Model model,
            @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
            @RequestParam(name = "pageSize", required = false, defaultValue = "8") Integer pageSize,
            @RequestParam(name = "titleSearch", required = false) String titleSearch
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        Page<Doctor> Doctor;

        if (titleSearch != null && !titleSearch.isEmpty()) {
            Doctor = doctorService.findAllByUserFullNameAndUserStatusTrue(titleSearch, pageable);
        } else {
            Doctor = doctorService.findAllByUserStatusTrue(pageable);
        }

        model.addAttribute("titleSearch", titleSearch);
        model.addAttribute("doctors", Doctor);
        model.addAttribute("numberOfPage", Doctor.getTotalPages());

        return "landing/doctor/doctors";
    }
}
