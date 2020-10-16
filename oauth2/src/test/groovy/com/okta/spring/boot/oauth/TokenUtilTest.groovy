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
package com.okta.spring.boot.oauth

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.testng.annotations.Test

import static org.mockito.Mockito.*
import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat

class TokenUtilTest {

    @Test
    void tokenScopesToAuthorities_emptyScopesTest() {

        def token = mock(OAuth2AccessToken)
        when(token.getScopes()).thenReturn(Collections.emptySet())

        assertThat TokenUtil.tokenScopesToAuthorities(token), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenScopesToAuthorities_nullScopesTest() {

        def token = mock(OAuth2AccessToken)
        when(token.getScopes()).thenReturn(null)

        assertThat TokenUtil.tokenScopesToAuthorities(token), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenScopesToAuthorities_nullTokenTest() {
        assertThat TokenUtil.tokenScopesToAuthorities(null), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenScopesToAuthorities_withScopesTest() {
        def token = mock(OAuth2AccessToken)
        when(token.getScopes()).thenReturn(new HashSet<>(["A", "b", "see"]))

        assertThat TokenUtil.tokenScopesToAuthorities(token), both(
                                                                hasItems(
                                                                    new SimpleGrantedAuthority("SCOPE_A"),
                                                                    new SimpleGrantedAuthority("SCOPE_b"),
                                                                    new SimpleGrantedAuthority("SCOPE_see"))).and(
                                                                hasSize(3))
    }

    @Test
    void tokenClaimsToAuthorities_emptyMapTest() {
        assertThat TokenUtil.tokenClaimsToAuthorities(Collections.emptyMap(), "a-key"), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenClaimsToAuthorities_nullMapTest() {
        assertThat TokenUtil.tokenClaimsToAuthorities(null, "a-key"), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenClaimsToAuthorities_nullKeyTest() {
        def attributes = [one: "two"]
        assertThat TokenUtil.tokenClaimsToAuthorities(attributes, null), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenClaimsToAuthorities_keyMissTest() {
        def attributes = [one: "two"]
        assertThat TokenUtil.tokenClaimsToAuthorities(attributes, "something-else"), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenClaimsToAuthorities_notStringArrayValueTest() {
        def attributes = [groups: [complex: "object", goes: "here"]]
        assertThat TokenUtil.tokenClaimsToAuthorities(attributes, "groups"), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenClaimsToAuthorities_stringValueTest() {
        def attributes = [simple: "foo"]
        assertThat TokenUtil.tokenClaimsToAuthorities(attributes, "simple"), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void tokenClaimsToAuthorities_multipleValuesTest() {
        def attributes = [rolesHere: ["a", "B", "sEa"]]
        assertThat TokenUtil.tokenClaimsToAuthorities(attributes, "rolesHere"), both(
                                                                                                hasItems(
                                                                                                    new SimpleGrantedAuthority("a"),
                                                                                                    new SimpleGrantedAuthority("B"),
                                                                                                    new SimpleGrantedAuthority("sEa"))).and(
                                                                                                hasSize(3))
    }

    @Test
    void opaqueTokenClaimsToAuthorities_multipleValuesTest() {
        Collection<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("SCOPE_base"))

        def attributes = [rolesHere: ["a", "B", "sEa"]]
        assertThat TokenUtil.opaqueTokenClaimsToAuthorities(attributes, "rolesHere", authorities), both(
            hasItems(
                new SimpleGrantedAuthority("SCOPE_base"),
                new SimpleGrantedAuthority("a"),
                new SimpleGrantedAuthority("B"),
                new SimpleGrantedAuthority("sEa"))).and(
            hasSize(4))
    }

    @Test
    void issuerUri_rootOrgTest() {
        assertThat "issuer uri expected to be root/org)", TokenUtil.isRootOrgIssuer("https://sample.okta.com")
        assertThat "issuer uri expected to be root/org)", TokenUtil.isRootOrgIssuer("https://dev-12345.oktapreview.com/")
        assertThat "issuer uri expected to be root/org)", TokenUtil.isRootOrgIssuer("https://example.io")
    }

    @Test
    void issuerUri_nonRootOrgTest() {
        assertThat "issuer uri expected to be non-root/org)", !TokenUtil.isRootOrgIssuer("https://sample.okta.com/oauth2/default")
        assertThat "issuer uri expected to be non-root/org)", !TokenUtil.isRootOrgIssuer("https://example.io/oauth2/ausvd5ple5TRRsbcJ0h7")
    }
}