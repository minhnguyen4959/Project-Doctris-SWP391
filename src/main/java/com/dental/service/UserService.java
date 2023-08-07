package com.dental.service;

import com.dental.entity.Patient;
import com.dental.entity.User;
import com.dental.repository.PatientRepository;
import com.dental.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.util.List;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;
    @Autowired
    PatientRepository patientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    User getUserByEmail(String email){
        return userRepository.findByEmail(email);
    }

    public List<User> getAllUser(){
        return userRepository.findAll();
    }

    public void save(User user) {
        userRepository.save(user);
    }

    public void updateUserStatus(boolean status, int userId) {
        userRepository.updateUserStatus(status, userId);
    }

    public void updateUser(String fullName, boolean status, int id) {
        userRepository.setUserInfoById(fullName, status, id);
    }

    public User getByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public void addUser(User user) {
        userRepository.save(user);
    }

    public User get(int id) {
        return userRepository.findById(id).get();
    }


    public void delete(int id) {
        userRepository.deleteById(id);
    }

    public User update(User user, String newPassword){
        user.setPassword(passwordEncoder.encode(newPassword));
        return userRepository.save(user);
    }

    public void registerUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setStatus(true);
        user.setRole("Patient");
        userRepository.save(user);
        Patient patient = new Patient();

        User user1 = userRepository.findByEmail(user.getEmail());
        patient.setUser(user1);
        System.out.println(patient);
        patientRepository.save(patient);
    }

    public boolean checkEmail(String email) {
        return userRepository.findByEmail(email) != null;
    }

    public void updateToken(String token, String email){
        User user = userRepository.findByEmail(email);
        if (user != null){
            user.setToken(token);
            userRepository.save(user);
        }else {
            //exception
        }
    }

    public User findByToken(String token){
        return userRepository.findByToken(token) ;
    }

    public void updatePassword(User user, String newPassword){
        String encodePassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodePassword);
        user.setToken(null);
        userRepository.save(user);
    }

    public Page<User> findAllByStatusAndFullNameAndRole(boolean status , String fullName, String role, Pageable pageable) {
        return userRepository.findAllByStatusAndFullNameContainingAndRole(status, fullName, role, pageable);
    }

    public Page<User> findAllByStatusAndFullName(boolean status ,String fullName, Pageable pageable) {
        return userRepository.findAllByStatusAndFullNameContaining(status, fullName, pageable);
    }

    public Page<User> findAllByStatusAndRole(boolean status ,String role, Pageable pageable) {
        return userRepository.findAllByStatusAndRole(status, role, pageable);
    }

    public Page<User> findAllByFullNameAndRole(String fullName ,String role, Pageable pageable) {
        return userRepository.findAllByFullNameContainingAndRole(fullName, role, pageable);
    }

    public Page<User> findAllByFullName(String fullName, Pageable pageable) {
        return userRepository.findAllByFullNameContaining(fullName, pageable);
    }

    public Page<User> findAllByStatus(boolean status, Pageable pageable) {
        return userRepository.findAllByStatus(status, pageable);
    }

    public Page<User> findAllByRole(String role, Pageable pageable) {
        return userRepository.findAllByRole(role, pageable);
    }

    public Page<User> findAll(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    public int countEmployeeActive(boolean status){
        return userRepository.countEmployeeActive(status);
    }


}
