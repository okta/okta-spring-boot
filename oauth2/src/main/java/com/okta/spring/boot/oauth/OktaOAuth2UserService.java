/*
 * Copyright 2018-Present Okta, Inc.
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

import com.okta.spring.boot.oauth.http.Auth0ClientRequestInterceptor;
import com.okta.spring.boot.oauth.http.UserAgentRequestInterceptor;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Collection;

final class OktaOAuth2UserService extends DefaultOAuth2UserService {

    private final Collection<AuthoritiesProvider> authoritiesProviders;

    OktaOAuth2UserService(Collection<AuthoritiesProvider> authoritiesProviders) {
        this.authoritiesProviders = authoritiesProviders;
        setRestOperations(restOperations());
    }

    private RestOperations restOperations() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());
        restTemplate.getInterceptors().add(new Auth0ClientRequestInterceptor());
        return restTemplate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User user = super.loadUser(userRequest);
        return UserUtil.decorateUser(user, userRequest, authoritiesProviders);
    }
}