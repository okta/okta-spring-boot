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
package com.okta.spring.tests.oauth2.code;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
@RestController
// fail loading this config if the SDK 'Client' is found. It should NOT exist on the classpath by default
@ConditionalOnMissingClass("com.okta.sdk.client.Client")
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class BasicRedirectCodeFlowApplication {

    @GetMapping("/")
    @PreAuthorize("hasAuthority('SCOPE_email')")
    public String getMessageOfTheDay(Principal principal) {
        return "Welcome home, The message of the day is boring: " + principal.getName();
    }

// The following isn't needed as the equivalent is provided by Spring Boot Security by default
    @Configuration
    static class WebConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated()
                .and().oauth2Client()
                .and().oauth2Login();

            // disable csrf to make testing easier
            http.csrf().disable();
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(BasicRedirectCodeFlowApplication.class, args);
    }
}