package com.ra.demospringbootspringsecurityjwt.repositories;

import com.ra.demospringbootspringsecurityjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
}
