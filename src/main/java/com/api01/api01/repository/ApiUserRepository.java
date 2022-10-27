package com.api01.api01.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.api01.api01.entity.APIUser;

public interface ApiUserRepository extends JpaRepository<APIUser, String> {

}
