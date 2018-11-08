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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class SignInWidgetConfigController {

    private final String issuer;

    private final  String clientId;

    public SignInWidgetConfigController(@Value("${okta.oauth2.issuer}") String issuer,
                                        @Value("${okta.oauth2.client-id}") String clientId) {
        this.issuer = issuer;
        this.clientId = clientId;
    }

    @GetMapping("/sign-in-widget-config")
    public WidgetConfig getWidgetConfig() {
        return new WidgetConfig(issuer, clientId);
    }

    public static class WidgetConfig {
        public String baseUrl;
        public String clientId;
        public Map<String, Object> authParams = new LinkedHashMap<>();

        public WidgetConfig(String issuer, String clientId) {

            this.clientId = clientId;
            this.authParams.put("issuer", issuer);
            this.baseUrl = issuer.replaceAll("/oauth2/.*", "");
        }
    }
}
