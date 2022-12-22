/*
 * Copyright 2017 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity(securedEnabled = true)
public class RedirectCodeFlowApplication {

    public static void main(String[] args) {
        SpringApplication.run(RedirectCodeFlowApplication.class, args);
    }

// By default Spring configures the equivalent for you. Secure by default.

//    @Configuration
//    static class SecurityConfig {
//        @Bean
//        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//            http.authorizeHttpRequests()
//                .anyRequest().authenticated()
//                .and().oauth2Client()
//                .and().oauth2Login()
//                .and().oauth2ResourceServer().jwt()
//            return http.build();
//        }
//    }
}