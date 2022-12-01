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
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;

/**
 * Allows for custom {@link GrantedAuthority}s to be added to the current OAuth Principal. Multiple implementations
 * are allowed, by default OAuth scopes are converted to Authorities with the format {@code SCOPE_<scope-name>} and
 * if a `groups` claim exists in the access or id token, those are converted as well.
 *
 * Example usage:
 *
 * <pre><code>
 *     &#64;Bean
 *     AuthoritiesProvider myCustomAuthoritiesProvider() {
 *         return (user, userRequest) -&gt; lookupExtraAuthoritesByName(user.getAttributes().get("email"));
 *     }
 * </code></pre>
 *
 * @since 1.4.0
 */
public interface AuthoritiesProvider {

    Collection<? extends GrantedAuthority> getAuthorities(OAuth2User user, OAuth2UserRequest userRequest);

    default Collection<? extends GrantedAuthority> getAuthorities(OidcUser user, OidcUserRequest userRequest) {
        return getAuthorities((OAuth2User) user, userRequest);
    }

    /**
     * Returns collections of authorities based on the contents of a JWT or other Bearer token.
     * @param token a bearer token
     * @return A collections of authorities based on the contents of a JWT or other Bearer token.
     * @since 2.2.0
     */
    default Collection<GrantedAuthority> getAuthorities(Jwt token) {
        return Collections.emptySet();
    }
}
