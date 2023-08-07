package com.dental.controller;


import com.dental.entity.User;
import com.dental.entity.UserDetailsImpl;
import com.dental.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RedirectController {

    @Autowired
    private HttpSession session;

    @Autowired
    UserService userService;

    @GetMapping("/redirect")
    public String redirect(@AuthenticationPrincipal UserDetailsImpl userDetails, Model model) {
        User userEnity = userDetails.getUserEntity();
        User u = userService.get(userEnity.getUserId());
//        System.out.println(userEnity);

        session.setAttribute("user", userEnity);
        session.setAttribute("u", u);
        System.out.println(u);
        if (userEnity!= null){
            if (userEnity.getRole().equals("Admin") || userEnity.getRole().equals("Staff")){
                return "redirect:/admin";
            } else {
                return "redirect:/";
//                return "landing/index";
            }
        }
        return "landing/auth/login"; // Redirect to login page if role not found
    }



    @GetMapping("/access-denied")
    public String deniedAccess(){
        return "landing/error";
    }

}
