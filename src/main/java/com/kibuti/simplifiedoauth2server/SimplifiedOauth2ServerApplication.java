package com.kibuti.simplifiedoauth2server;

import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.Roles;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.RolesRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SimplifiedOauth2ServerApplication implements CommandLineRunner {


    @Autowired
    private RolesRepository roleRepository;


    public static void main(String[] args) {
        SpringApplication.run(SimplifiedOauth2ServerApplication.class, args);
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Override
    public void run(String... args) throws Exception {
        createRoleIfNotExists("ROLE_USER");
        createRoleIfNotExists("ROLE_SUPER_ADMIN");
    }

    private void createRoleIfNotExists(String roleName) {
        Roles existingRole = roleRepository.findByRoleName(roleName).orElse(null);

        if (existingRole == null) {
            Roles newRole = new Roles();
            newRole.setRoleName(roleName);
            roleRepository.save(newRole);
        }
    }

}
