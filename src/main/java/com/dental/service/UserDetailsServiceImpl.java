package com.dental.service;

import com.dental.entity.User;
import com.dental.entity.UserDetailsImpl;
import com.dental.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private HttpSession session;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userTest = userRepository.findByEmail(username);

        if(userTest != null && !userTest.isStatus()){
            session.setAttribute("messageLockUser", "The account is locked !");
            session.setMaxInactiveInterval(5);
            throw new UsernameNotFoundException("User not found");
        }
        Optional<User> user = Optional.ofNullable(userRepository.findByEmail(username));
        return user.map(UserDetailsImpl::new).orElseThrow(()-> new UsernameNotFoundException("user not found: "+ username));

    }
}
