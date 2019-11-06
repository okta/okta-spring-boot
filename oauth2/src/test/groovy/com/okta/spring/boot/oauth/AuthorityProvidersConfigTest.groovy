/*
 * Copyright 2020-Present Okta, Inc.
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
package com.okta.spring.boot.oauth

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.user.OAuth2User
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.both
import static org.hamcrest.Matchers.hasItems
import static org.hamcrest.Matchers.hasSize
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

/**
 * Tests for AuthorityProvidersConfig.
 * @since 1.4
 */
class AuthorityProvidersConfigTest {

    @Test
    void tokenScopesAuthoritiesProvider() {
        def token = mock(OAuth2AccessToken)
        when(token.getScopes()).thenReturn(new HashSet<>(["A", "b"]))

        def request = mock(OAuth2UserRequest)
        when(request.getAccessToken()).thenReturn(token)

        assertThat new AuthorityProvidersConfig().tokenScopesAuthoritiesProvider().getAuthorities(null, request), both(
            hasItems(
                new SimpleGrantedAuthority("SCOPE_A"),
                new SimpleGrantedAuthority("SCOPE_b"))).and(
            hasSize(2))
    }

    @Test
    void groupClaimsAuthoritiesProvider() {
        def attributes = [rolesHere: ["a", "B"]]
        def user = mock OAuth2User
        when(user.getAttributes()).thenReturn(attributes)

        OktaOAuth2Properties props = new OktaOAuth2Properties()
        props.setGroupsClaim("rolesHere")

        assertThat new AuthorityProvidersConfig().groupClaimsAuthoritiesProvider(props).getAuthorities(user, null), both(
            hasItems(
                new SimpleGrantedAuthority("a"),
                new SimpleGrantedAuthority("B"))).and(
            hasSize(2))
    }
}
