/*
 * Copyright 2017 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
package com.okta.spring.tests.common.servlet.code;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

import static com.okta.spring.boot.oauth.Okta.configureOAuth2WithPkceAndAuthReqParams;

@SpringBootApplication
@RestController
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class BasicRedirectCodeFlowApplication {

    @GetMapping("/")
    @PreAuthorize("hasAuthority('SCOPE_email')")
    public String getMessageOfTheDay(Principal principal) {
        return "Welcome home, The message of the day is boring: " + principal.getName();
    }

    @GetMapping("/everyone")
    @PreAuthorize("hasAuthority('Everyone')")
    public String everyoneAccess(Principal principal) {
        return "Everyone has Access: " + principal.getName();
    }

    @GetMapping("/invalidGroup")
    @PreAuthorize("hasAuthority('invalidGroup')")
    public String invalidGroup() {
        throw new IllegalStateException("Test exception, user should not have access to this method");
    }

// The following isn't needed as the equivalent is provided by Spring Boot Security by default
    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
       http.authorizeRequests().anyRequest().authenticated();
       configureOAuth2WithPkceAndAuthReqParams(http, clientRegistrationRepository);
       http.oauth2Client();

        // disable csrf to make testing easier
       http.csrf().disable();

       return http.build();
    }

    public static void main(String[] args) {
        SpringApplication.run(BasicRedirectCodeFlowApplication.class, args);
    }
}
