package com.dental.controller;

import com.dental.entity.*;
import com.dental.service.BlogService;
import com.dental.service.CommentService;
import com.dental.service.UserService;
import com.dental.util.Const;
import com.dental.util.UploadFile;
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
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Controller
@RequestMapping()
public class BlogController {

    @Autowired
    BlogService blogService;

    @Autowired
    CommentService commentService;

    @Autowired
    UserService userService;

    // ADMIN PAGE
    @GetMapping("admin/blog")
    public String getAll(
        Model model,
        @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
        @RequestParam(name = "pageSize", required = false, defaultValue = "8") Integer pageSize,
        @RequestParam(name = "titleSearch", required = false) String titleSearch,
        @RequestParam(name = "statusSearch", required = false) String statusSearch
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        List<Blog> blogs = blogService.getAll();
        Page<Blog> Blog;

        if (titleSearch != null && !titleSearch.isEmpty() && statusSearch != null && !statusSearch.isEmpty()){
            boolean status = true;
            if (statusSearch.equals("0")) {
                status = false;
            }

            Blog = blogService.findAllByStatusAndTitleContaining(status, titleSearch, pageable);
        } else if (statusSearch != null && !statusSearch.isEmpty()) {
            boolean status = true;
            if (statusSearch.equals("0")) {
                status = false;
            }
            Blog = blogService.findAllByStatus(status, pageable);
        } else if (titleSearch != null && !titleSearch.isEmpty()) {
            Blog = blogService.findAllByTitleContaining(titleSearch, pageable);
        } else {
            Blog = blogService.findAll(pageable);
        }

        model.addAttribute("titleSearch", titleSearch);
        model.addAttribute("statusSearch", statusSearch);
        model.addAttribute("usesPage", Blog);
        model.addAttribute("numberOfPage", Blog.getTotalPages());
        model.addAttribute("blogs", blogs);

        return "admin/blog/blogs";
    }

    @GetMapping("admin/blog/{blogId}")
    public String getOne(
            @PathVariable("blogId") int blogId,
            Model model,
            @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
            @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR_HOME) Integer pageSize
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        Blog blog = blogService.get(blogId);
        Page<CommentBlog> commentsByBlogId = commentService.getAllByBlogId(blogId, pageable);
        User user = userService.get(blog.getUser().getUserId());

        List<Blog> reverseBlogs = blogService.getAll();
        Collections.reverse(reverseBlogs);
        model.addAttribute("blog", blog);
        model.addAttribute("user", user);
        model.addAttribute("reverseBlogs", reverseBlogs);
        model.addAttribute("comments", commentsByBlogId);
        model.addAttribute("numberOfPage", commentsByBlogId.getTotalPages());

        return "admin/blog/blog-detail";
    }

    @GetMapping("admin/blog/add")
    public String addBlogForm(Model model) {
        model.addAttribute("blog", new Blog());

        return "admin/blog/add-blog";
    }

    @PostMapping("admin/blog/save")
    public String createBlog(@Valid Blog blog, BindingResult result, @RequestParam("image") MultipartFile multipartFile, Model model) {
        if (multipartFile.isEmpty()) {
            model.addAttribute("image", "Thumbnail must be mandatory");
        }

        if (result.hasErrors() || multipartFile.isEmpty()) {
            return "admin/blog/add-blog";
        }


        try {
            String filename = UploadFile.saveFile(multipartFile);
//            String fileName = UploadFile.getFileName(multipartFile);
            blog.setThumbnail(filename);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            blogService.save(blog);
            return "redirect:/admin/blog";
        } catch (Error e) {
            System.out.println(e);
            return "admin/blog/add-blog";
        }
    }

    @GetMapping("admin/blog/edit/{blogId}")
    public String editBlog(@PathVariable("blogId") int blogId, Model model) {
        Blog blog = blogService.get(blogId);

        model.addAttribute("blog", blog);
        return "admin/blog/update-blog";
    }

    @PostMapping("admin/blog/update")
    public String updateBlog(@Valid Blog blog, BindingResult result, Model model, @RequestParam(value = "image", required = false) MultipartFile multipartFile) {
        int blogId = blog.getBlogId();

        Blog b = blogService.get(blogId);
        blog.setUser(b.getUser());
        blog.setCreatedAt(b.getCreatedAt(""));

        if (result.hasErrors()) {
            return "admin/blog/update-blog";
        }

        if (multipartFile != null) {
            String fileName = UploadFile.getFileName(multipartFile);

            if (!fileName.isEmpty()) {
                try {
                    String filename = UploadFile.saveFile(multipartFile);
                    blog.setThumbnail(filename);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        try {
            blogService.save(blog);
            return "redirect:/admin/blog/" + blogId;
        } catch (Error e) {
            System.out.println(e);
            return "admin/blog/update-blog";
        }
    }

    @PostMapping("admin/blog/delete/{blogId}")
    public String deleteUser(@PathVariable("blogId") int blogId, Model model) throws IllegalAccessException {
        try {
            blogService.get(blogId);
            blogService.delete(blogId);
        } catch (Error e) {
            throw new IllegalAccessException("Failed to delete!");
        }
        return "redirect:/admin/blog";
    }

    // USER PAGE
    @GetMapping("/blog")
    public String getAllBlog(
        Model model,
        @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
        @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR_HOME) Integer pageSize,
        @RequestParam(name = "titleSearch", required = false) String titleSearch
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        List<Blog> blogs = blogService.getAll();
        Page<Blog> Blog;

        if (titleSearch != null && !titleSearch.isEmpty()) {
            Blog = blogService.findAllByTitleContainingAndStatusTrueOrderByCreatedAtDesc(titleSearch, pageable);
        } else {
            Blog = blogService.findAllByStatusTrueOrderByCreatedAtDesc(pageable);
        }

        model.addAttribute("titleSearch", titleSearch);
        model.addAttribute("usesPage", Blog);
        model.addAttribute("numberOfPage", Blog.getTotalPages());
        model.addAttribute("blogs", blogs);

        return "landing/blog/blogs";
    }

    @GetMapping("/blog/{blogId}")
    public String getOneBlog(
        @PathVariable("blogId") int blogId,
        Model model,
        @AuthenticationPrincipal UserDetailsImpl userDetails,
        @RequestParam(name = "page", required = false, defaultValue = Const.PAGE_DEFAULT_STR) Integer pageNum,
        @RequestParam(name = "pageSize", required = false, defaultValue = Const.PAGE_SIZE_DEFAULT_STR) Integer pageSize
    ) {
        if (pageNum < 1) {
            pageNum = 1;
        }

        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        Blog blog = blogService.get(blogId);
        Page<CommentBlog> commentsByBlogId = commentService.findAllByBlogBlogIdOrderByCreatedAtDesc(blogId, pageable);

        List<Blog> blogs = blogService.findAllByStatusTrueOrderByCreatedAtDesc();

        if (userDetails != null) {
            User user = userDetails.getUserEntity();
            model.addAttribute("user", user);
        }

        model.addAttribute("comment", new CommentBlog());
        model.addAttribute("blog", blog);
        model.addAttribute("blogs", blogs);
        model.addAttribute("comments", commentsByBlogId);
        model.addAttribute("numberOfPage", commentsByBlogId.getTotalPages());

        return "landing/blog/blog-detail";
    }
}
