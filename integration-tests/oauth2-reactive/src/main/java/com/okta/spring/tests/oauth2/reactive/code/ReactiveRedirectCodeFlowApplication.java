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
package com.okta.spring.tests.oauth2.reactive.code;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Date;

@SpringBootApplication
@RestController
@EnableReactiveMethodSecurity
public class ReactiveRedirectCodeFlowApplication {

    @GetMapping(value = "/")
    public Message getMessageOfTheDay(Principal principal) {
        return new Message("Welcome home, The message of the day is boring: " + principal.getName());
    }

    @EnableWebFluxSecurity
    static class SecurityConfiguration {

        @Bean
        public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
            return http
                    .authorizeExchange()
                    .anyExchange().authenticated()
                    .and()
                    .oauth2Login()
                    .and().build();
        }
    }

    static class Message {
        public Date date = new Date();
        public String text;

        Message(String text) {
            this.text = text;
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(ReactiveRedirectCodeFlowApplication.class, args);
    }
}