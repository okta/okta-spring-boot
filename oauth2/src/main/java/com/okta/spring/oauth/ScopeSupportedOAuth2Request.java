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

import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.Collection;

public class ScopeSupportedOAuth2Request extends OAuth2Request {

    private static final long serialVersionUID = 42L;

    public ScopeSupportedOAuth2Request(OAuth2Request other) {
        super(other);
    }

    @Override
    @SuppressWarnings("PMD.UselessOverridingMethod")
    public void setScope(Collection<String> scope) {
        super.setScope(scope);
    }
}
