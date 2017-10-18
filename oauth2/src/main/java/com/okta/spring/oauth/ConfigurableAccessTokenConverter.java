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
package com.okta.spring.oauth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Adjusts the default map of JWT access token claims based on a configurable scope and role claim field.
 * @since 0.1.0
 */
public class ConfigurableAccessTokenConverter extends DefaultAccessTokenConverter {

    private static final String SUBJECT_CLAIM = "sub";

    private final String scopeClaim;
    private final String rolesClaim;

    public ConfigurableAccessTokenConverter(String scopeClaim, String rolesClaim) {
        Assert.hasText(scopeClaim, "scopeClaim cannot be null or empty.");
        Assert.hasText(rolesClaim, "rolesClaim cannot be null or empty.");
        this.scopeClaim = scopeClaim;
        this.rolesClaim = rolesClaim;
    }

    private Map<String, ?> tweakScopeMap(Map<String, ?> map) {
        Map<String, Object> tokenMap = new LinkedHashMap<>(map);
        if (tokenMap.containsKey(scopeClaim)) {
            Object scope = tokenMap.get(scopeClaim);
            if (!ObjectUtils.isEmpty(scope)) {
                tokenMap.put(OAuth2AccessToken.SCOPE, scope);
            }
        }

        if (tokenMap.containsKey(rolesClaim)) {
            Object roles = tokenMap.get(rolesClaim);
            if (!ObjectUtils.isEmpty(roles)) {
                tokenMap.put(UserAuthenticationConverter.AUTHORITIES, roles);
            }
        }

        if (tokenMap.containsKey(SUBJECT_CLAIM)) {
            Object sub = tokenMap.get(SUBJECT_CLAIM);
            tokenMap.put(UserAuthenticationConverter.USERNAME, sub);
        }

        return tokenMap;
    }

    @Override
    public OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map) {
        return super.extractAccessToken(value, tweakScopeMap(map));
    }

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        OAuth2Authentication originalOAuth2Authentication = super.extractAuthentication(tweakScopeMap(map));

        Authentication originalUserAuthentication = originalOAuth2Authentication.getUserAuthentication();
        if (originalUserAuthentication != null) {
            UsernamePasswordAuthenticationToken newToken = new UsernamePasswordAuthenticationToken(originalUserAuthentication.getPrincipal(),
                    "N/A",
                    originalUserAuthentication.getAuthorities());
            newToken.setDetails(Collections.unmodifiableMap(map));
            return new OAuth2Authentication(originalOAuth2Authentication.getOAuth2Request(), newToken);
        }
        return originalOAuth2Authentication;
    }
}