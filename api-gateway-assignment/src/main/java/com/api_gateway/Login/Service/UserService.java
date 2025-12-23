package com.api_gateway.Login.Service;

import com.api_gateway.Login.model.User;
import com.api_gateway.Login.Repository.UserRepository;
import com.api_gateway.Login.Service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void updatePassword(User user, String newPassword) {
        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$";
        if (!newPassword.matches(regex)) {
            throw new RuntimeException("Password must be 12+ chars with uppercase, lowercase, number, and special character.");
        }

        for (String oldPassHash : user.getPasswordHistory()) {
            if (passwordEncoder.matches(newPassword, oldPassHash)) {
                throw new RuntimeException("Cannot reuse any of your last 5 passwords.");
            }
        }
        user.getPasswordHistory().add(user.getPassword());
        if (user.getPasswordHistory().size() > 5) {
            user.getPasswordHistory().remove(0);
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordLastChanged(LocalDateTime.now());
        user.setIsDefaultPassword(false);
        userRepository.save(user);
    }
}