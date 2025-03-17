package com.kibuti.simplifiedoauth2server.GlobeSecurity;


import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.ItemReadyExistException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.GlobeUserRepository;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final GlobeUserRepository globeUserRepository;

    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        GlobeUserEntity user = globeUserRepository.findUserMangerByUserName(username)
                .orElseThrow(() -> new ItemReadyExistException("User with given username not found: " + username));

        Set<GrantedAuthority> authorities =
                user.getRoles()
                        .stream()
                        .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                        .collect(Collectors.toSet());

        return new User(user.getUserName(),
                user.getPassword(),
                authorities);
    }
}

