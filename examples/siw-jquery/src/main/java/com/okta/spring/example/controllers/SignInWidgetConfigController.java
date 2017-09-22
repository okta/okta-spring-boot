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

import com.okta.spring.oauth.OktaProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.LinkedHashMap;
import java.util.Map;


@EnableConfigurationProperties(OktaProperties.class)
@RestController
public class SignInWidgetConfigController {

    private final String issuerUrl;

    private final  String clientId;

    public SignInWidgetConfigController(OktaProperties OAuthProperties) {

        Assert.notNull(OAuthProperties.getOauth2().getClientId(), "Property 'okta.oauth.clientId' is required.");
        this.issuerUrl = OAuthProperties.getOauth2().getIssuer();
        this.clientId = OAuthProperties.getOauth2().getClientId();
    }


    @GetMapping("/sign-in-widget-config")
    public WidgetConfig getWidgetConfig() {
        return new WidgetConfig(issuerUrl, clientId);
    }

    @XmlRootElement
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
