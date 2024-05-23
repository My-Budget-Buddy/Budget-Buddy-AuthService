package com.skillstorm.authservice.repositories;

import com.skillstorm.authservice.models.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Integer> {

    Optional<UserCredentials> findByUsername(String username);

    boolean existsByUsername(String username);

    @Query("SELECT u.id FROM UserCredentials u WHERE u.username = ?1")
    Optional<Integer> findIdByUsername(String username);

}
