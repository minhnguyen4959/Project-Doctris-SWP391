package com.dental.service;

import com.dental.entity.CommentBlog;
import com.dental.repository.CommentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CommentService {

    @Autowired
    CommentRepository commentRepository;

    public List<CommentBlog> getAll() {
        return commentRepository.findAll();
    }

    public CommentBlog get(int id) {
        return commentRepository.findById(id).get();
    }

    public Page<CommentBlog> getAllByBlogId(int blogId, Pageable pageable) {
        return commentRepository.findAllByBlogBlogId(blogId, pageable);
    }

    public void save(CommentBlog rateStar) {
        commentRepository.save(rateStar);
    }

    public void delete(int id) {
        commentRepository.deleteById(id);
    }

    public Page<CommentBlog> findAll(Pageable pageable) {
        return commentRepository.findAll(pageable);
    }

    public Page<CommentBlog> findAllByBlogBlogIdOrderByCreatedAtDesc(int blogId, Pageable pageable) {
        return commentRepository.findAllByBlogBlogIdOrderByCreatedAtDesc(blogId, pageable);
    }
}
