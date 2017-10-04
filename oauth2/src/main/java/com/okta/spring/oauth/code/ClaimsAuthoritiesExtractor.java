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
package com.okta.spring.oauth.code;

import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ClaimsAuthoritiesExtractor implements AuthoritiesExtractor {

    private final String rolesClaimKey;

    public ClaimsAuthoritiesExtractor(String rolesClaimKey) {
        this.rolesClaimKey = rolesClaimKey;
    }

    @Override
    public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
        // extract the string groups from map
        List groups= Collections.emptyList();
        if (map.containsKey(rolesClaimKey)) {
            Object rawGroups = map.get(rolesClaimKey);
            if (rawGroups instanceof List) {
                groups = (List) rawGroups;
            }
        }

        // convert them to authorities
        return (List<GrantedAuthority>) groups.stream()
                .filter(String.class::isInstance)
                .map(group -> new SimpleGrantedAuthority(group.toString()))
                .collect(Collectors.toList());
    }
}
