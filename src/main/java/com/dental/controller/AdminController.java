package com.dental.controller;

import com.dental.entity.User;
import com.dental.service.AppointmentService;
import com.dental.service.BlogService;
import com.dental.service.DoctorService;
import com.dental.service.RateStarService;
import com.dental.service.SService;
import com.dental.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDate;

@Controller
public class AdminController {

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

    @Autowired
    AppointmentService appointmentService;

    @Autowired
    SService sService;

    @GetMapping("/admin")
    public String viewHomeAdminPage(Model model) {
        User user = new User();
        int numberPatient = appointmentService.countAllPatientBooking();
        double revenue = appointmentService.getTotalRevenue();
        int numberEmployeeActive = userService.countEmployeeActive(true);
        int numberServices = sService.countNumberServices();
        int numberAppointments = appointmentService.countAppointments();


        model.addAttribute("numberPatient", numberPatient);
        model.addAttribute("revenue", revenue);
        model.addAttribute("numberEmployeeActive", numberEmployeeActive);
        model.addAttribute("numberServices", numberServices);
        model.addAttribute("numberAppointments", numberAppointments);


        return "admin/index";
    }


    @GetMapping("/chart-data")
    @ResponseBody
    public ChartDataResponse getChartData(@RequestParam("option") String option, @RequestParam("type") String type) {
        ChartDataResponse response = new ChartDataResponse();
        double[] data;
        String[] categories1 = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        int year = year = Integer.parseInt(option);;
        if (type.equals("chart1")){
            double revenueCurrent;
                data = new double[12];
                for (int month = 1; month < 13; month++) {
                    revenueCurrent = appointmentService.getRevenueByMonth(year,month);
                    data[month - 1] = revenueCurrent;
                }

                response.setData(data);
                response.setCategories(categories1);
            if (data == null) {
                data = new double[0];
            }
        }else{
            double appointmentNumber = 0;
                data = new double[12];

                for (int month = 1; month < 13; month++) {
                    appointmentNumber = appointmentService.countAppointmentByMonth(year,month);
                    data[month - 1] = appointmentNumber;
                }
                response.setData(data);
                response.setCategories(categories1);
        }



        return response;
    }

    static class ChartDataResponse {
        private double[] data;
        private String[] categories;

        // Getters and setters

        public double[] getData() {
            return data;
        }

        public void setData(double[] data) {
            this.data = data;
        }

        public String[] getCategories() {
            return categories;
        }

        public void setCategories(String[] categories) {
            this.categories = categories;
        }
    }
}
