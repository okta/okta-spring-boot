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
package com.okta.spring.example.resources;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.bind.annotation.XmlRootElement;

@RestController
public class WelcomeResource {

    /**
     * Simple example REST endpoint that returns a static message.  This resource also serves as an example for checking
     * an OAuth scope and client roles (parsed from an access token).
     * @return a static welcome message
     */
    @GetMapping("/welcome")
    @PreAuthorize("#oauth2.clientHasRole('Everyone') || #oauth2.hasScope('email')")
    public Welcome getMessageOfTheDay() {
        return new Welcome("The message of the day is boring.");
    }

    @XmlRootElement
    public static class Welcome {
        public String messageOfTheDay;

        public Welcome(String messageOfTheDay) {
            this.messageOfTheDay = messageOfTheDay;
        }
    }
}
