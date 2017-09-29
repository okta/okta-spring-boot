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

import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;

import java.util.Map;

/**
 * A {@link PrincipalExtractor} pulls a {@link java.security.Principal Principal}, out of a configurable claim
 * based on the {code}principalClaimKey{code}.
 * @since 0.2.0
 */
public class ClaimsPrincipalExtractor implements PrincipalExtractor {

    private final String principalClaimKey;

    public ClaimsPrincipalExtractor(String principalClaimKey) {
        this.principalClaimKey = principalClaimKey;
    }

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        return map.get(principalClaimKey);
    }
}
