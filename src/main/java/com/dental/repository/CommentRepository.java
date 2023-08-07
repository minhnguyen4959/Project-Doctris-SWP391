package com.dental.repository;

import com.dental.entity.CommentBlog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CommentRepository extends JpaRepository<CommentBlog, Integer> {
    Page<CommentBlog> findAll(Pageable pageable);
    Page<CommentBlog> findAllByBlogBlogIdOrderByCreatedAtDesc(int blogId, Pageable pageable);
    Page<CommentBlog> findAllByBlogBlogId(int blogId, Pageable pageable);
}
