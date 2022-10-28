package com.api01.api01.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.api01.api01.security.APIUserDetailsService;
import com.api01.api01.security.filter.APILoginFilter;
import com.api01.api01.security.filter.TokenCheckFilter;
import com.api01.api01.security.handler.APILoginSuccessHandler;
import com.api01.api01.util.JWTUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Configuration
@Log4j2
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class CustomSecurityConfig {

    // 주입
    private final APIUserDetailsService apiUserDetailsService;

    private final JWTUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("------------------------web configure------------------------");
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        log.info("----------configure-----------");

        // AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationmanagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);

        authenticationmanagerBuilder
                .userDetailsService(apiUserDetailsService)
                .passwordEncoder(passwordEncoder());

        // Get AuthenticationManager
        AuthenticationManager authenticatioManager = authenticationmanagerBuilder.build();

        // 반드시 필요
        http.authenticationManager(authenticatioManager);

        // APILoginFilter
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticatioManager);

        // APILoginSuccessHandler
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);
        // SuccesHandler 세팅
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);

        // APILoginFilter의 위치 조정
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        // api로 시작하는 모든 경로는 TokenCheckFilter 동작
        http.addFilterBefore(
                tokenCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        http.csrf().disable(); // csrf 토큰의 비활성화
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션을 사용하지 않음

        return http.build();
    }

    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil) {
        return new TokenCheckFilter(jwtUtil);
    }

}
