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
package com.okta.spring.example.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class WelcomeController {

    /**
     * Simple example REST endpoint that returns a static message.  This controller also serves as an example for checking
     * an OAuth scope and client roles (parsed from an access token).
     * @return a static welcome message
     */
    @GetMapping("/")
    public Welcome getMessageOfTheDay(Principal principal) {
        return new Welcome("The message of the day is boring.", principal.getName());
    }

    public static class Welcome {
        public String messageOfTheDay;
        public String username;

        public Welcome() {}

        public Welcome(String messageOfTheDay, String username) {
            this.messageOfTheDay = messageOfTheDay;
            this.username = username;
        }
    }

    @GetMapping("/everyone")
    @PreAuthorize("hasAuthority('Everyone')")
    public String everyoneRole() {
        return "Okta Groups have been mapped to Spring Security authorities correctly!";
    }
}
