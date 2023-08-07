package com.dental.controller;

import com.dental.entity.Doctor;
import com.dental.entity.Patient;
import com.dental.entity.User;
import com.dental.entity.UserDetailsImpl;
import com.dental.service.PatientService;
import com.dental.service.UserService;
import com.dental.util.Const;
import com.dental.util.UploadFile;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("")
public class PatientController {

    @Autowired
    UserService userService;

    @Autowired
    PatientService patientService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/patient/profile")
    public String viewProfile(@AuthenticationPrincipal UserDetailsImpl userDetails, Model model) {
        model.addAttribute("user", userDetails.getUserEntity());
        return "landing/patient/patient-profile";
    }

//    @PostMapping("/change-password")
//    public String changePassword(
//            @AuthenticationPrincipal UserDetailsImpl userDetails,
//            @RequestParam("currentPassword") String currentPassword,
//            @RequestParam("newPassword") String newPassword,
//            @RequestParam("confirmPassword") String confirmPassword,
//            Model model,
//            RedirectAttributes redirectAttributes) {
//        String url = "landing/patient/patient-profile";
//        User userEntity = userDetails.getUserEntity();
//        String message = "";
//
//        //login success
//        if (userEntity != null) {
//            // password correct
//            if (passwordEncoder.matches(currentPassword, userEntity.getPassword())) {
//                //current Password not same new password
//                if (!currentPassword.equals(newPassword)) {
//                    //confirm password
//                    if (newPassword.equals(confirmPassword)) {
//                        userEntity = userService.update(userEntity, newPassword);
//                        userDetails.setUserEntity(userEntity);
//                        redirectAttributes.addFlashAttribute("passwordMessage", "Change password success");
////                        return "redirect:/patient/profile";
//                        return "redirect:/patient/profile";
//                    } else {
//                        message = "Confirm password not same !!!";
//                    }
//                } else {
//                    message = "Please enter new password different old password!!!";
//                }
//            } else {
//                message = "Wrong password !";
//            }
//        } else {
//            message = "Please login !!!";
//        }
//
//        model.addAttribute("message", message);
//        model.addAttribute("user", userEntity);
//        return "landing/patient/patient-profile";
//    }

    @GetMapping("/admin/patient")
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
            List<Patient> patients = patientService.getAll();
            Page<Patient> Patient;

            boolean status = true;
            if (statusSearch != null && statusSearch.equals("0")) {
                status = false;
            }

            if (fullName != null && !fullName.isEmpty() && statusSearch != null && !statusSearch.isEmpty() && gender != null && !gender.isEmpty()){
                Patient = patientService.findAllByUserStatusAndUserFullNameAndUserGender(status, fullName, gender, pageable);
            } else if (gender != null && !gender.isEmpty() && fullName != null && !fullName.isEmpty()){
                Patient = patientService.findAllByUserFullNameAndUserGender(fullName, gender, pageable);
            } else if (gender != null && !gender.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
                Patient = patientService.findAllByUserStatusAndUserGender(status, gender, pageable);
            } else if (fullName != null && !fullName.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
                Patient = patientService.findAllByUserStatusAndUserFullName(status, fullName, pageable);
            } else if (statusSearch != null && !statusSearch.isEmpty()) {
                Patient = patientService.findAllByUserStatus(status, pageable);
            } else if (fullName != null && !fullName.isEmpty()) {
                Patient = patientService.findAllByUserFullName(fullName, pageable);
            } else if (gender != null && !gender.isEmpty()) {
                Patient = patientService.findAllByUserGender(gender, pageable);
            } else {
                Patient = patientService.findAll(pageable);
            }

            model.addAttribute("fullName", fullName);
            model.addAttribute("statusSearch", statusSearch);
            model.addAttribute("usesPage", Patient);
            model.addAttribute("numberOfPage", Patient.getTotalPages());
            model.addAttribute("patients", patients);

            return "admin/patient/patients1";
    }
//
    @GetMapping("admin/patient/edit/{patientId}")
    public String showPatientUpdate(@PathVariable("patientId") int patientId, Model model) {
        Patient patient = patientService.getPatientById(patientId);
        List<Patient> patients = patientService.getAll();
        User user = userService.get(patient.getUser().getUserId());
        model.addAttribute("patient", patient);
        model.addAttribute("patients", patients);
        model.addAttribute("user", user);
        return "admin/patient/update-patient";

    }

    @PostMapping("admin/patient/update")
    public String updatePatient(
            @Valid Patient patient, BindingResult patientBindingResult,
            @Valid User user, BindingResult userBindingResult,
            Model model, @RequestParam(value = "image", required = false) MultipartFile multipartFile,
            RedirectAttributes redirectAttributes
    ) {
        int patientId = user.getUserId();

        User u = userService.get(patientId);
        user.setPatient(u.getPatient());

        user.setEmail(u.getEmail());
        user.setPassword(u.getPassword());
        user.setRole(u.getRole());
        user.setFullName(u.getFullName());
        user.setDateOfBirth(u.getDateOfBirth());
        user.setPhoneNumber(u.getPhoneNumber());
        user.setGender(u.getGender());
        user.setAddress(u.getAddress());
        user.setCreatedAt(u.getCreatedAt());

        if (patientBindingResult.hasErrors() || userBindingResult.hasErrors()) {
            return "admin/patient/update-patient";
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
            patientService.updatePatient(patient.getBloodGroup(), patientId);
            userService.updateUserStatus(user.isStatus(), patientId);
            redirectAttributes.addFlashAttribute("message", "Update successful");
            return "redirect:/admin/patient/edit/" + patientId;
        } catch (Error e) {
            System.out.println(e);
            redirectAttributes.addFlashAttribute("message", "Update fail");
//            model.addAttribute("message", "Update fail");
//            return "admin/patient/update-patient";
            return "redirect:/admin/patient/edit/" + patientId;
        }
    }

    @GetMapping("admin/patient/add")
    public String showPatientAdd(Model model) {
        Patient patient = new Patient();
        User user = new User();
        model.addAttribute("patient", patient);
        model.addAttribute("user", user);
        return "admin/patient/add-patient1";
    }


//
//    @GetMapping("{}")
//    public String detailPatient() {
//        return "";
//    }
//
//    public String updatePatient(){
//        return "";
//    }

}
