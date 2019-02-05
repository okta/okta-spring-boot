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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

final class UserUtil {

    private UserUtil() {}

    static OAuth2User decorateUser(OAuth2User user, OAuth2UserRequest userRequest, String groupClaim) {

        // Only post process requests from the "Okta" reg
        if (!"Okta".equals(userRequest.getClientRegistration().getClientName())) {
            return user;
        }

        // start with authorities from super
        Set<GrantedAuthority> authorities = new HashSet<>(user.getAuthorities());
        // add 'SCOPE_' authorities
        authorities.addAll(TokenUtil.tokenScopesToAuthorities(userRequest.getAccessToken()));
        // add any authorities extracted from the 'group' claim
        authorities.addAll(TokenUtil.tokenClaimsToAuthorities(user.getAttributes(), groupClaim));

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        return new DefaultOAuth2User(authorities, user.getAttributes(), userNameAttributeName);
    }

    static OidcUser decorateUser(OidcUser user, OidcUserRequest userRequest, String groupClaim) {

        // Only post process requests from the "Okta" reg
        if (!"Okta".equals(userRequest.getClientRegistration().getClientName())) {
            return user;
        }

        // start with authorities from super
        Set<GrantedAuthority> authorities = new HashSet<>(user.getAuthorities());
        // add 'SCOPE_' authorities
        authorities.addAll(TokenUtil.tokenScopesToAuthorities(userRequest.getAccessToken()));
        // add any authorities extracted from the 'group' claim
        authorities.addAll(TokenUtil.tokenClaimsToAuthorities(user.getAttributes(), groupClaim));

        String userNameAttributeName = userRequest.getClientRegistration()
            .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        return StringUtils.hasText(userNameAttributeName)
                ? new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo(), userNameAttributeName)
                : new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo());
    }
}