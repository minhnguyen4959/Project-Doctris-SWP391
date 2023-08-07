package com.dental.service;

import com.dental.entity.Blog;
import com.dental.repository.BlogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class BlogService {

    @Autowired
    BlogRepository blogRepository;

    public List<Blog> getAll() {
        return blogRepository.findAll();
    }

    public Blog get(int id) {
        return blogRepository.findById(id).get();
    }

    public void save(Blog blog) {
        blogRepository.save(blog);
    }

    public void delete(int id) {
        blogRepository.deleteById(id);
    }

    public Page<Blog> findAll(Pageable pageable) {
        return blogRepository.findAll(pageable);
    }

    public Page<Blog> findAllByStatusAndTitleContaining(boolean status ,String title, Pageable pageable) {
        return blogRepository.findAllByStatusAndTitleContaining(status, title, pageable);
    }

    public Page<Blog> findAllByTitleContaining(String title, Pageable pageable) {
        return blogRepository.findAllByTitleContaining(title, pageable);
    }

    public Page<Blog> findAllByStatus(boolean status, Pageable pageable) {
        return blogRepository.findAllByStatus(status, pageable);
    }

    public Page<Blog> findAllByUser(Integer userId, Pageable pageable) {
        return blogRepository.findAllByUser(userId, pageable);
    }

    // User Page
    public List<Blog> findAllByStatusTrueOrderByCreatedAtDesc() {
        return blogRepository.findAllByStatusTrueOrderByCreatedAtDesc();
    }

    public Page<Blog> findAllByStatusTrueOrderByCreatedAtDesc(Pageable pageable) {
        return blogRepository.findAllByStatusTrueOrderByCreatedAtDesc(pageable);
    }

    public Page<Blog> findAllByTitleContainingAndStatusTrueOrderByCreatedAtDesc(String title, Pageable pageable) {
        return blogRepository.findAllByTitleContainingAndStatusTrueOrderByCreatedAtDesc(title, pageable);
    }
}
