package com.api01.api01.repository;

import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.api01.api01.entity.APIUser;

import lombok.extern.log4j.Log4j2;

@SpringBootTest
@Log4j2
public class APIUserRepositoryTests {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ApiUserRepository apiUserRepository;

    @Test
    public void testInserts() {
        IntStream.range(1, 100).forEach(i -> {
            APIUser apiUser = APIUser.builder()
                    .mid("apiuser" + i)
                    .mpw(passwordEncoder.encode("1111"))
                    .build();

            apiUserRepository.save(apiUser);
        });
    }

}
