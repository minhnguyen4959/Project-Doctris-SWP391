package com.dental.controller;

import com.dental.entity.User;
import com.dental.entity.UserDetailsImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
@RequestMapping()
public class LoginController {

    @Autowired
    private HttpSession session;

    @GetMapping("/login")
    public String login(@AuthenticationPrincipal UserDetailsImpl userDetails, HttpServletRequest request, HttpServletResponse response, Model model) throws ServletException, IOException {


        if ( userDetails != null){
            System.out.println("------------------");
//            System.out.println(userDetails.getUserEntity());
//        session.setAttribute("user", user);
            return "redirect:/";
        }else {
            model.addAttribute("success", request.getParameter("success"));
        }
            return "landing/auth/login";
    }

    public UserDetails getLoggedInUser(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("auth: "+auth);
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken))
        {
            System.out.println("check auth");

            if(auth.getDetails() !=null)
                System.out.println(auth.getDetails().getClass());
            if( auth.getDetails() instanceof UserDetails)
            {
                System.out.println("UserDetails");
            }
            else
            {
                System.out.println("!UserDetails");
            }
        }
        return null;
    }

    @GetMapping("/logout-success")
    public String handleLogoutSuccess(){
        System.out.println("xu ly logout");
        User user = (User) session.getAttribute("user");
        return "redirect:/";
    }



}
