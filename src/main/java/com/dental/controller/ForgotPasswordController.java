package com.dental.controller;

import com.dental.entity.User;
import com.dental.repository.UserRepository;
import com.dental.service.UserService;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.SneakyThrows;
import net.bytebuddy.utility.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
//import net.bytebuddy.utility.RandomString;

@Controller
@RequestMapping
public class ForgotPasswordController {

    @Autowired
    private UserService userService;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private HttpSession session;

    @GetMapping("/forgot_password")
    public String showForgetPasswordForm(Model model){
        model.addAttribute("title", "Forgot Password");
        return "landing/auth/forgot-password-form";
    }

    @PostMapping("/forgot_password")
    public String handleForgetPassword(@RequestParam(name = "email") String email, HttpServletRequest request,Model model){


        String token = RandomString.make(5).toUpperCase();
        userService.updateToken(token, email);
        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(2);
        session.setAttribute("storedEmail", email);
        session.setAttribute("storedToken", token);
        session.setAttribute("storedExpirationTime", expirationTime);

        sendMail(email, token);
        model.addAttribute("token", token);
        return "landing/auth/forgot-password-form";
    }



    @SneakyThrows
    private void sendMail(String email, String token) {
        MimeMessage message = mailSender.createMimeMessage();
        System.out.println("message="+message);
        MimeMessageHelper helper = new MimeMessageHelper(message);
        System.out.println("helper="+helper);
        helper.setFrom("minhnguyenhhhh@gmail.com","Forgot password 22222");
        helper.setTo(email);

        String subject = "This is your token";
        String content = "<h2> This is your code reset password: "+"<span style='color: red'>"+token+"</span>"+"</h2>";
        helper.setSubject(subject);
        helper.setText(content, true);
        mailSender.send(message);
    }

    @PostMapping("check_token")
    public String viewFormForgotPassword(@RequestParam(name = "token") String token, Model model){
        LocalDateTime expirationTime = (LocalDateTime) session.getAttribute("storedExpirationTime");
        String storedToken = (String) session.getAttribute("storedToken");

        if (storedToken == null || storedToken.isEmpty() || expirationTime == null){
            model.addAttribute("message", "fail");
            return "landing/auth/forgot-password-form";
        }

        if (token.equals(storedToken)) {
            // Check if the expiration time has not passed
            LocalDateTime currentTime = LocalDateTime.now();
            if (currentTime.isBefore(expirationTime)) {
                // OTP code is valid
                model.addAttribute("token", token);
                return "landing/auth/new-password";
            }else{
            model.addAttribute("messageTime", "expired");
            return "landing/auth/forgot-password-form";
            }
        }else{
            model.addAttribute("message", "fail");
        }

        return "landing/auth/forgot-password-form";
    }


    @PostMapping("reset_password")
    public String handleResetPassword(@RequestParam(name = "token") String token,
                                      @RequestParam(name = "newPassword") String password,
                                      @RequestParam(name = "confirmPassword") String confirmPassword,
                                      Model model){
        User user = userService.findByToken(token);
        if (user == null){
            model.addAttribute("resetPasswordMessage","fail");
            return "landing/auth/forgot-password-form";
        }else{
            model.addAttribute("resetPasswordMessage","success");
            userService.updatePassword(user, password);
            return "landing/auth/login";
        }
    }



    @PostMapping("/check_email")
    public ResponseEntity<Map<String, Boolean>> checkEmailExistence(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        User user = userService.getByEmail(email);
        boolean exists = (user == null) ? false : true;
        Map<String, Boolean> response = new HashMap<>();
        response.put("exists", exists);
        return ResponseEntity.ok(response);
    }


}
