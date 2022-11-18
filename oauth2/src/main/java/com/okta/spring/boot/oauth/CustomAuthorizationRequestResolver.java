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
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.okta.spring.boot.oauth.OktaOAuth2CustomParam.ACR_VALUES;
import static com.okta.spring.boot.oauth.OktaOAuth2CustomParam.ENROLL_AMR_VALUES;
import static com.okta.spring.boot.oauth.OktaOAuth2CustomParam.MAX_AGE;
import static com.okta.spring.boot.oauth.OktaOAuth2CustomParam.PROMPT;

/**
 * Allows custom query param values to be sent in /authorize call to Okta backend.
 */
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;

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
        System.out.println("====================== enter resolve 1 ============== " + request.getRequestURI() + "," + request.getQueryString());

        OAuth2AuthorizationRequest req = defaultResolver.resolve(request);

        if (req != null) {
            System.out.println("====================== enter resolve 1 a============== ");
            req = customizeOktaAuthorizationReq(req);
        } else {
            System.out.println("====================== enter resolve 1 b============== ");
        }

        return req;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        System.out.println("====================== enter resolve 2 ============== ");

        OAuth2AuthorizationRequest req = defaultResolver.resolve(request, clientRegistrationId);

        if (req != null) {
            System.out.println("====================== enter resolve 2 a============== ");
            req = customizeOktaAuthorizationReq(req);
        } else {
            System.out.println("====================== enter resolve 2 b============== ");
        }

        return req;
    }

    private OAuth2AuthorizationRequest customizeOktaAuthorizationReq(OAuth2AuthorizationRequest req) {

        Map<String, Object> extraParams = new LinkedHashMap<>(req.getAdditionalParameters());

        if (Strings.hasText(this.acrValues)) {
            extraParams.put(ACR_VALUES, this.acrValues);
        }

        if (Strings.hasText(enrollAmrValues)) {
            extraParams.put(ENROLL_AMR_VALUES, enrollAmrValues);
        }

        if (Strings.hasText(prompt)) {
            extraParams.put(PROMPT, prompt);

            // Okta enforced restrictions
            if (prompt.equals("enroll_authenticator")) {
                return OAuth2AuthorizationRequest
                    .from(req)
                    .authorizationRequestUri(buildCustomAuthorizationRequestUri(req))
                    .build();
            }
        }

        return OAuth2AuthorizationRequest
            .from(req)
            .additionalParameters(extraParams)
            .build();
    }

    private String buildCustomAuthorizationRequestUri(OAuth2AuthorizationRequest req) {
        //UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8)

        return UriComponentsBuilder
            .fromUriString(req.getAuthorizationUri())
            .replaceQueryParam("response_type", Collections.emptyList())
            .queryParam(ACR_VALUES, "urn:okta:2fa:any:ifpossible")
            .queryParam(MAX_AGE, "0")
            .build(true)
            .toUriString();
    }

}
