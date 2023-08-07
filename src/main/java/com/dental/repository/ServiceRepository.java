package com.dental.repository;

import com.dental.entity.Blog;
import com.dental.entity.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

@Repository
public interface ServiceRepository extends JpaRepository<Service, Integer> {
    List<Service> findAllByServiceIdIn(List<Integer> services);

    Page<Service> findAll(Pageable pageable);

    Page<Service> findAllByStatusAndTitleContaining(boolean status, String title, Pageable pageable);

    Page<Service> findAllByTitleContaining(String title, Pageable pageable);

    Page<Service> findAllByStatus(boolean status, Pageable pageable);

    @Transactional
    @Query("SELECT s, AVG(r.star) FROM Service s LEFT JOIN s.rateStar r GROUP BY r.service.serviceId")
    List<Object[]> findAllServicesWithAverageStar();

    // User Page
    List<Service> findAllByStatusTrueOrderByCreatedAtDesc();

    Page<Service> findAllByTitleContainingAndStatusTrueOrderByCreatedAtDesc(String title, Pageable pageable);

    Page<Service> findAllByStatusTrueOrderByCreatedAtDesc(Pageable pageable);

    @Query("SELECT COUNT(s) FROM Service s WHERE s.status = true")
    int countNumberServices();
}
