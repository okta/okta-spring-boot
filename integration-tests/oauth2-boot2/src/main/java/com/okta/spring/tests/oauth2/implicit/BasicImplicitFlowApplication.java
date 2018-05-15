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
package com.okta.spring.tests.oauth2.implicit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@EnableResourceServer
@SpringBootApplication
public class BasicImplicitFlowApplication {

    public static void main(String[] args) {
        SpringApplication.run(BasicImplicitFlowApplication.class, args);
    }

    @EnableGlobalMethodSecurity(prePostEnabled = true)
    protected static class GlobalSecurityConfiguration extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            return new OAuth2MethodSecurityExpressionHandler();
        }
    }

    @Configuration
    @Order(0)
    static class ResourceSecurityConfigurer extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .antMatchers(HttpMethod.OPTIONS,"/**").permitAll()
                    .anyRequest().authenticated();
        }
    }

    @RestController
    @CrossOrigin(origins = "http://localhost:8080")
    public static class MessageOfTheDayController {

        @GetMapping("/api/userProfile")
        @PreAuthorize("#oauth2.hasScope('profile')")
        public Map<String, Object> getUserDetails(OAuth2Authentication authentication) {
            return (Map<String, Object>) authentication.getUserAuthentication().getDetails();
        }

        @GetMapping("/api/messages")
        @PreAuthorize("#oauth2.hasScope('email')")
        public Map<String, Object> messages() {

            Map<String, Object> result = new HashMap<>();
            result.put("messages", Arrays.asList(
                    new Message("I am a robot."),
                    new Message("Hello, word!")
            ));

            return result;
        }

        @GetMapping("/")
        @PreAuthorize("#oauth2.hasScope('email')")
        public String getMessageOfTheDay(Principal principal) {
            return "The message of the day is boring: " + principal.getName();
        }

        @GetMapping("/everyone")
        @PreAuthorize("hasAuthority('Everyone')")
        public String everyoneAccess(Principal principal) {
            return "Everyone has Access: " + principal.getName();
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