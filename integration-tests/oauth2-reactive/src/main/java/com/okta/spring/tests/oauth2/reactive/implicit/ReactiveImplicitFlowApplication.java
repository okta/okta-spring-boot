/*
 * Copyright 2019-Present Okta, Inc.
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
package com.okta.spring.tests.oauth2.reactive.implicit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@EnableReactiveMethodSecurity
public class ReactiveImplicitFlowApplication {

    public static void main(String[] args) {
        SpringApplication.run(ReactiveImplicitFlowApplication.class, args);
    }

    @EnableWebFluxSecurity
    static class SecurityConfiguration {

        @Bean
        public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
            return http
                .authorizeExchange()
                    .anyExchange().authenticated()
                    .and()
                .oauth2ResourceServer()
                    .jwt().and().and().build();
            }
    }

    @RestController
    @CrossOrigin(origins = "http://localhost:8080")
    public static class MessageOfTheDayController {

        @GetMapping("/api/userProfile")
        @PreAuthorize("hasAuthority('SCOPE_profile')")
        public Mono<Map<String, Object>> getUserDetails(Authentication authentication) {
            // TODO: validate this is the correct way to get the details
            return Mono.just((Map<String, Object>) authentication.getDetails());
        }

        @GetMapping("/api/messages")
        @PreAuthorize("hasAuthority('SCOPE_email')")
        public Mono<Map<String, Object>> messages() {

            Map<String, Object> result = new HashMap<>();
            result.put("messages", Arrays.asList(
                    new Message("I am a robot."),
                    new Message("Hello, world!")
            ));

            return Mono.just(result);
        }

        @GetMapping("/")
        @PreAuthorize("hasAuthority('SCOPE_email')")
        public Mono<String> getMessageOfTheDay(Principal principal) {
            return Mono.just("The message of the day is boring: " + principal.getName());
        }

        @GetMapping("/everyone")
        @PreAuthorize("hasAuthority('Everyone')")
        public Mono<String> everyoneAccess(Principal principal) {
            return Mono.just("Everyone has Access: " + principal.getName());
        }
    }

    static class Message {
        public Date date = new Date();
        public String text;

        Message(String text) {
            this.text = text;
        }
    }
}