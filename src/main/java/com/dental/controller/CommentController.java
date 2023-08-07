package com.dental.controller;

import com.dental.entity.*;
import com.dental.service.CommentService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping()
public class CommentController {

    @Autowired
    CommentService commentService;

    @PostMapping("/comment/save")
    public String createComment(
            @Valid CommentBlog comment,
            BindingResult result,
            Model model,
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            RedirectAttributes redirectAttrs
    ) {
        if (userDetails == null) {
            return "redirect:/";
        }

        if (result.hasErrors()) {
            redirectAttrs.addFlashAttribute("description", "Comment is mandatory");
            return "redirect:/blog/" + comment.getBlog().getBlogId();
        }

        try {
            comment.setUser(userDetails.getUserEntity());
            commentService.save(comment);
            return "redirect:/blog/" + comment.getBlog().getBlogId();
        } catch (Error e) {
            redirectAttrs.addFlashAttribute("description", e);
            return "redirect:/blog/" + comment.getBlog().getBlogId();

        }
    }
}
