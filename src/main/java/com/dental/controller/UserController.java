package com.dental.controller;

import com.dental.entity.Blog;
import com.dental.entity.Doctor;
import com.dental.entity.Patient;
import com.dental.entity.RateStar;
import com.dental.entity.Service;
import com.dental.entity.User;
import com.dental.entity.UserDetailsImpl;
import com.dental.service.BlogService;
import com.dental.service.DoctorService;
import com.dental.service.RateStarService;
import com.dental.service.SService;
import com.dental.service.UserService;
import com.dental.util.Const;
import com.dental.util.UploadFile;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.time.LocalDate;
import java.time.Period;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import java.util.List;
import java.util.Map;

@Controller
public class UserController {

    @Autowired
    private HttpSession session;

    @Autowired
    UserService userService;

    @Autowired
    DoctorService doctorService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Autowired
    BlogService blogService;

    @Autowired
    SService serviceService;

    @Autowired
    RateStarService rateStarService;

    @GetMapping("/")
    public String viewHomeLandingPage(@AuthenticationPrincipal UserDetailsImpl userDetails, Model model) {
        User userEnity = null;
        if (userDetails != null) {
            userEnity = userDetails.getUserEntity();
        }
        List<Service> top4Service = getTop4Service();
        List<Doctor> doctors = doctorService.getAll();
        List<Blog> blogs = blogService.getAll();

        List<RateStar> rateStars = rateStarService.getAll();
        List<RateStar> rateStarsTop5 = rateStarService.findTop5ByStarGreaterThanOrderByStarDesc(3);
        List<Object[]> servicesWithAVG = rateStarService.findTop4WithAvg();


        model.addAttribute("user", userEnity);
        model.addAttribute("top4Service", top4Service);
        model.addAttribute("doctors", doctors);
        model.addAttribute("blogs", blogs);
        model.addAttribute("rateStars", rateStars);
        model.addAttribute("rateStarsTop5", rateStarsTop5);
        model.addAttribute("servicesWithAVG", servicesWithAVG);
        return "landing/index";
//        return "landing/index-two";
// test link: http://localhost:8888/user/homeLanding

    }

    public List<Service> getTop4Service() {
        List<Service> top4Service = new ArrayList<>();
        int count = 0;
        List<Object[]> servicesWithAVG = rateStarService.findTop4WithAvg();
        for (Object[] serviceWithAVG : servicesWithAVG) {
            if (count < 4) {
                int id = (Integer) serviceWithAVG[0];
                Service service = serviceService.get(id);
                top4Service.add(service);
            }
            count++;
        }
        return top4Service;
    }


    @GetMapping("/bo")
    public String viewHomeAdminPage(Model model) {
        User user = new User();
        user.setFullName("Nguyen Van B");
        return "admin/index";
    }

//    @GetMapping("/error")
//    public String viewTest(Model model) {
//        User user = new User();
//        user.setFullName("Nguyen Van B");
//        return "landing/error";
//    }

    @PostMapping()
    public void registerUser(@ModelAttribute("") User user) {
        userService.addUser(user);
    }

    @GetMapping("/register")
    public String showRegister(Model model) {
        User user = new User();
        model.addAttribute("user", user);
        return "landing/auth/signup";
    }

    @PostMapping("/register/save")
    public String registration(@ModelAttribute("user") User user,
                               BindingResult result,
                               Model model) {
        System.out.println(user);
        String message = "";
        if (user == null) {
            message = "Register fail";
        } else {
            userService.registerUser(user);
            message = "Register successful";
        }
        return "redirect:/login";
    }

    @RequestMapping(value = "/checkEmailExists", method = RequestMethod.GET)
    @ResponseBody
    public Map<String, Object> checkEmailExists(@RequestParam String email) {
        Map<String, Object> response = new HashMap<>();
        boolean exists = userService.checkEmail(email);
        response.put("exists", exists);
        return response;
    }

    @GetMapping("/profile")
    public String profile(
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            Model model
    ) {
        String role = userDetails.getUserEntity().getRole();
        if (role.equals("Doctor")) {
            model.addAttribute("doctor", doctorService.get(userDetails.getUserEntity().getUserId()));
        }

        model.addAttribute("user", userService.get(userDetails.getUserEntity().getUserId()));
        return "landing/user/profile";
    }

    @PostMapping("/change-password")
    public String changePassword(
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @RequestParam("currentPassword") String currentPassword,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            Model model,
            RedirectAttributes redirectAttributes) {
        User userEntity = userDetails.getUserEntity();
        String message = "";

        // Check if user is logged in
        if (userEntity != null) {
            // Check if current password is correct
            if (passwordEncoder.matches(currentPassword, userEntity.getPassword())) {
                // Check if new password is different from the current password
                if (!currentPassword.equals(newPassword)) {
                    // Check if new password matches the confirm password
                    if (newPassword.equals(confirmPassword)) {
                        // Update the user's password
                        userEntity = userService.update(userEntity, newPassword);
                        userDetails.setUserEntity(userEntity);
//                        redirectAttributes.addFlashAttribute("passwordMessage", "Change password success");
                        model.addAttribute("passwordMessage", "Change password success");
                        return "redirect:/profile";
                    } else {
                        message = "Confirm password does not match!";
                    }
                } else {
                    message = "Please enter a new password different from the old password!";
                }
            } else {
                message = "Wrong password!";
            }
        } else {
            message = "Please login!";
        }

        redirectAttributes.addFlashAttribute("message", message);
        model.addAttribute("message", message);
        return "redirect:/profile";
    }

    @PostMapping("profile/update")
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
        user.setStatus(u.isStatus());
        user.setCreatedAt(u.getCreatedAt());

        if (user.getGender() == null) {
            model.addAttribute("gender", "Gender must be mandatory");
        }

        if (user.getDateOfBirth() == null) {
            hasErr = true;
            model.addAttribute("dateOfBirth", "Date of birth must be mandatory");
        } else {
            LocalDate birthDate = user.getDateOfBirth().toLocalDate();
            LocalDate currentDate = LocalDate.now();
            Period age = Period.between(birthDate, currentDate);

            if (u.getRole().equals("Patient")) {
                if (age.getYears() <= 1) {
                    hasErr = true;
                    model.addAttribute("dateOfBirth", "Your age must be greater than 2");
                }
            } else {
                if (age.getYears() < 20) {
                    hasErr = true;
                    model.addAttribute("dateOfBirth", "Your age must be greater than 20");
                }
            }
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
        } else {
            user.setAvatar(u.getAvatar());
        }

        if (doctorBindingResult.hasErrors() || userBindingResult.hasErrors() || hasErr) {
            return "landing/user/profile";
        }

        try {
            if (user.getRole().equals("Doctor")) {
                doctorService.updateDoctor(doctor.getDescription(), doctorId);
            }

            userService.save(user);
            session.setAttribute("user", userService.get(user.getUserId()));
            return "redirect:/profile";
        } catch (Error e) {
            System.out.println(e);
            return "landing/user/profile";
        }
    }

    // ADMIN PAGE
    @GetMapping("/admin/user")
    public String getAll(
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
            @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR) Integer pageSize,
            @RequestParam(name = "fullName", required = false) String fullName,
            @RequestParam(name = "statusSearch", required = false) String statusSearch,
            @RequestParam(name = "role", required = false) String role
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        if (userDetails != null && !userDetails.getUserEntity().getRole().equals("Admin")) {
            return "redirect:/admin";
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        Page<User> User;

        boolean status = true;
        if (statusSearch != null && statusSearch.equals("0")) {
            status = false;
        }

        if (fullName != null && !fullName.isEmpty() && statusSearch != null && !statusSearch.isEmpty() && role != null && !role.isEmpty()){
            User = userService.findAllByStatusAndFullNameAndRole(status, fullName, role, pageable);
        } else if (role != null && !role.isEmpty() && fullName != null && !fullName.isEmpty()){
            User = userService.findAllByFullNameAndRole(fullName, role, pageable);
        } else if (role != null && !role.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
            User = userService.findAllByStatusAndRole(status, role, pageable);
        } else if (fullName != null && !fullName.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
            User = userService.findAllByStatusAndFullName(status, fullName, pageable);
        } else if (statusSearch != null && !statusSearch.isEmpty()) {
            User = userService.findAllByStatus(status, pageable);
        } else if (fullName != null && !fullName.isEmpty()) {
            User = userService.findAllByFullName(fullName, pageable);
        } else if (role != null && !role.isEmpty()) {
            User = userService.findAllByRole(role, pageable);
        } else {
            User = userService.findAll(pageable);
        }

        model.addAttribute("fullName", fullName);
        model.addAttribute("statusSearch", statusSearch);
        model.addAttribute("role", role);
        model.addAttribute("users", User);
        model.addAttribute("numberOfPage", User.getTotalPages());

        return "admin/user/users";
    }

    @GetMapping("admin/user/user-add")
    public String addUserForm(Model model) {
        List<User> users = userService.getAllUser();
        model.addAttribute("user", new User());
        model.addAttribute("users", users);

        return "admin/user/add-user";
    }

    @PostMapping("admin/user/save")
    public String createUser(
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

        if (userBindingResult.hasErrors() || multipartFile.isEmpty() || u != null || hasErr) {
            List<User> users = userService.getAllUser();
            model.addAttribute("users", users);
            return "admin/user/add-user";
        }

        user.setPassword(passwordEncoder.encode("minh123456789"));
        user.setRole("Staff");

        try {
            String filename = UploadFile.saveFile(multipartFile);
            user.setAvatar(filename);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            userService.save(user);

            return "redirect:/admin/user";
        } catch (Error e) {
            System.out.println(e);
            return "admin/user/add-user";
        }
    }

    @GetMapping("admin/user/edit/{userId}")
    public String editDoctor(@PathVariable("userId") int userId, Model model) {
        User user = userService.get(userId);
        model.addAttribute("user", user);
        return "admin/user/update-user";
    }

    @PostMapping("admin/user/update")
    public String updateUser(
            @Valid User user, BindingResult userBindingResult,
            Model model, @RequestParam(value = "image", required = false) MultipartFile multipartFile
    ) {
        int userId = user.getUserId();
        boolean hasErr = false;

        User u = userService.get(userId);
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

        if (user.getGender() == null) {
            hasErr = true;
            model.addAttribute("gender", "Gender must be mandatory");
        }

        if (userBindingResult.hasErrors() || hasErr) {
            return "admin/user/update-user";
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
            userService.save(user);
            return "redirect:/admin/user";
        } catch (Error e) {
            System.out.println(e);
            return "admin/user/update-user";
        }
    }
}
