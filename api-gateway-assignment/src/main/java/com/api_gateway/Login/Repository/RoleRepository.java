package com.api_gateway.Login.Repository;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.api_gateway.Login.model.Erole;
import com.api_gateway.Login.model.Role;

import reactor.core.publisher.Mono;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(Erole name);
}


