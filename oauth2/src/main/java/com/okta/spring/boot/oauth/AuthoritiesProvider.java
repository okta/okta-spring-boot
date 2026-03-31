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
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
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
 * <p>Implementations may also override {@link #getAuthorities(Jwt)} and/or
 * {@link #getAuthorities(OAuth2AuthenticatedPrincipal)} to support Resource Server flows
 * (JWT and Opaque Token respectively).</p>
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
     * Returns additional authorities for a JWT resource server flow.
     * Override this method to provide custom authorities based on the JWT token.
     *
     * @param jwt the validated JWT
     * @return additional authorities; defaults to an empty collection
     * @since 3.1.1
     */
    default Collection<? extends GrantedAuthority> getAuthorities(Jwt jwt) {
        return Collections.emptyList();
    }

    /**
     * Returns additional authorities for an Opaque Token resource server flow.
     * Override this method to provide custom authorities based on the introspected token principal.
     *
     * @param principal the authenticated principal from token introspection
     * @return additional authorities; defaults to an empty collection
     * @since 3.1.1
     */
    default Collection<? extends GrantedAuthority> getAuthorities(OAuth2AuthenticatedPrincipal principal) {
        return Collections.emptyList();
    }
}
