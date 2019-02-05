/*
 * Copyright 2019-Present Okta, Inc.
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

import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import reactor.core.publisher.Mono;

final class ReactiveOktaOidcUserService extends OidcReactiveOAuth2UserService {

    private final String groupClaim;

    ReactiveOktaOidcUserService(String groupClaim) {
        this(groupClaim, new ReactiveOktaOAuth2UserService(groupClaim));
    }

    ReactiveOktaOidcUserService(String groupClaim, ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
        this.groupClaim = groupClaim;
        setOauth2UserService(oauth2UserService);
    }

    @Override
    public Mono<OidcUser> loadUser(OidcUserRequest userRequest) {
        return super.loadUser(userRequest).map(user -> UserUtil.decorateUser(user, userRequest,  groupClaim));
    }
}