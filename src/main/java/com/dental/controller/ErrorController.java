package com.dental.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {

    @GetMapping("/error")
    public String handleError() {
        // Return the path or view name of your custom 404 error page
        return "landing/error";
    }

//    @Override
//    public String getErrorPath() {
//        return "/error";
//    }
}
