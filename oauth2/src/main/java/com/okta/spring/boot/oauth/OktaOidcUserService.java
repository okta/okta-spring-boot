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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

final class OktaOidcUserService extends OidcUserService {

    private final String groupClaim;

    OktaOidcUserService(String groupClaim) {
        this.groupClaim = groupClaim;
        this.setOauth2UserService(new OktaOAuth2UserService(groupClaim));
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser user = super.loadUser(userRequest);

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