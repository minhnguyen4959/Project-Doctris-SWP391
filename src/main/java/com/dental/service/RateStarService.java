package com.dental.service;

import com.dental.entity.RateStar;
import com.dental.repository.RateStarRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RateStarService {

    @Autowired
    RateStarRepository rateStarRepository;

    public List<RateStar> getAll() {
        return rateStarRepository.findAll();
    }

    public RateStar get(int id) {
        return rateStarRepository.findById(id).get();
    }

    public RateStar saveRateStar(RateStar r) {
        return rateStarRepository.save(r);
    }

    public Page<RateStar> getAllByServiceId(int serviceId, Pageable pageable) {
        return rateStarRepository.findAllByServiceServiceId(serviceId, pageable);
    }

    public Page<RateStar> findAllByServiceServiceIdOrderByCreatedAtDesc(int serviceId, Pageable pageable) {
        return rateStarRepository.findAllByServiceServiceIdOrderByCreatedAtDesc(serviceId, pageable);
    }

    public void save(RateStar rateStar) {
        rateStarRepository.save(rateStar);
    }

    public void delete(int id) {
        rateStarRepository.deleteById(id);
    }

    public Page<RateStar> findAll(Pageable pageable) {
        return rateStarRepository.findAll(pageable);
    }

    public List<Object[]> findAllWithAvg() {
        return rateStarRepository.findAllWithAvg();
    }

    public List<Object[]> findTop4WithAvg() {
        return rateStarRepository.findTop4WithAvg();
    }


    public List<RateStar> findTop5ByStarGreaterThanOrderByStarDesc(int greater) {
        return rateStarRepository.findTop5ByStarGreaterThanOrderByStarDesc(greater);
    }

    public int countAllByUserUserIdAndServiceServiceId(int userId, int serviceId) {
        return rateStarRepository.countAllByUserUserIdAndServiceServiceId(userId, serviceId);
    }
}
