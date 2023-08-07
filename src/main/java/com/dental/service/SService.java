package com.dental.service;

import com.dental.entity.Blog;
import com.dental.entity.Service;
import com.dental.repository.ServiceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@org.springframework.stereotype.Service
public class SService  {
    @Autowired
    ServiceRepository serviceRepository;

    public List<Service> getAll() {
        return serviceRepository.findAll();
    }

    public List<Service> getAllByIds(List<Integer> services) {
        return serviceRepository.findAllByServiceIdIn(services);
    }

    public Service get(int id) {
        return serviceRepository.findById(id).get();
    }

    public void save(Service service) {
        serviceRepository.save(service);
    }

    public void delete(int id) {
        serviceRepository.deleteById(id);
    }

    public Page<Service> findAll(Pageable pageable) {
        return serviceRepository.findAll(pageable);
    }

    public Page<Service> findAllByStatusAndTitleContaining(boolean status ,String title, Pageable pageable) {
        return serviceRepository.findAllByStatusAndTitleContaining(status, title, pageable);
    }

    public Page<Service> findAllByTitleContaining(String title, Pageable pageable) {
        return serviceRepository.findAllByTitleContaining(title, pageable);
    }

    public Page<Service> findAllByStatus(boolean status, Pageable pageable) {
        return serviceRepository.findAllByStatus(status, pageable);
    }

    public List<Object[]> findAllServicesWithAverageStar() {
        return serviceRepository.findAllServicesWithAverageStar();
    }

    // User Page
    public List<Service> findAllByStatusTrueOrderByCreatedAtDesc() {
        return serviceRepository.findAllByStatusTrueOrderByCreatedAtDesc();
    }

    public Page<Service> findAllByStatusTrueOrderByCreatedAtDesc(Pageable pageable) {
        return serviceRepository.findAllByStatusTrueOrderByCreatedAtDesc(pageable);
    }

    public Page<Service> findAllByTitleContainingAndStatusTrueOrderByCreatedAtDesc(String title, Pageable pageable) {
        return serviceRepository.findAllByTitleContainingAndStatusTrueOrderByCreatedAtDesc(title, pageable);
    }

    public int countNumberServices(){
        return serviceRepository.countNumberServices();
    }
}
