/*
 * Copyright 2022-Present Okta, Inc.
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
package com.okta.spring.boot.oauth;

import com.okta.commons.lang.Strings;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Allows custom query param 'acr_values' to be sent in /authorize API call to Okta backend.
 */
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;

    private final String acrValues;

    private final String prompt;

    private final String enrollAmrValues;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                              String authorizationRequestBaseUri,
                                              String acrValues,
                                              String prompt,
                                              String enrollAmrValues) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be null");
        this.acrValues = acrValues;
        this.prompt = prompt;
        this.enrollAmrValues = enrollAmrValues;

        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {

        OAuth2AuthorizationRequest req = defaultResolver.resolve(request);

        if (req != null) {
            req = customizeOktaAuthorizationReq(req);
        }

        return req;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {

        OAuth2AuthorizationRequest req = defaultResolver.resolve(request, clientRegistrationId);

        if (req != null) {
            req = customizeOktaAuthorizationReq(req);
        }

        return req;
    }

    private OAuth2AuthorizationRequest customizeOktaAuthorizationReq(OAuth2AuthorizationRequest req) {

        Map<String, Object> extraParams = new HashMap<>(req.getAdditionalParameters());

        if (Strings.hasText(this.acrValues)) {
            extraParams.put(OktaOAuth2CustomParam.ACR_VALUES, this.acrValues);
        }

        if (Strings.hasText(prompt)) {
            extraParams.put(OktaOAuth2CustomParam.PROMPT, prompt);
        }

        if (Strings.hasText(enrollAmrValues)) {
            extraParams.put(OktaOAuth2CustomParam.ENROLL_AMR_VALUES, enrollAmrValues);
        }

        return OAuth2AuthorizationRequest
            .from(req)
            .additionalParameters(extraParams)
            .build();
    }
}
