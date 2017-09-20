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
package com.okta.spring.oauth.implicit

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class ConfigurableAccessTokenConverterTest {

    @Test
    void mapConversionTestWithScopeArray() {
        def scopeClaim = "custom_scope"
        def roleClaim = "custom_role"
        def accessTokenString = "an_access_token"
        def converter = new ConfigurableAccessTokenConverter(scopeClaim, roleClaim)
        def initialClaimMap = [
                custom_scope: ["my_custom_scope", "as_an_array"],
                custom_role: ["one_role", "two_role", "red_role", "blue_role"]
        ]
        def accessToken = converter.extractAccessToken(accessTokenString, initialClaimMap)
        assertThat accessToken.value, equalTo(accessTokenString)
        assertThat accessToken.scope, allOf(containsInAnyOrder("my_custom_scope", "as_an_array"), hasSize(2))
        assertThat accessToken.additionalInformation.get(UserAuthenticationConverter.AUTHORITIES), allOf(containsInAnyOrder("one_role", "two_role", "red_role", "blue_role"), hasSize(4))
    }

    @Test
    void mapConversionTestWithScopeString() {
        def scopeClaim = "custom_scope"
        def roleClaim = "custom_role"
        def accessTokenString = "an_access_token"
        def converter = new ConfigurableAccessTokenConverter(scopeClaim, roleClaim)
        def initialClaimMap = [
                custom_scope: "my_custom_scope as_an_array",
                custom_role: ["one_role", "two_role", "red_role", "blue_role"]
        ]
        def accessToken = converter.extractAccessToken(accessTokenString, initialClaimMap)
        assertThat accessToken.value, equalTo(accessTokenString)
        assertThat accessToken.scope, allOf(containsInAnyOrder("my_custom_scope", "as_an_array"), hasSize(2))
        assertThat accessToken.additionalInformation.get(UserAuthenticationConverter.AUTHORITIES),
                allOf(
                    containsInAnyOrder("one_role", "two_role", "red_role", "blue_role"),
                    hasSize(4))
    }

    @Test
    void mapConversionTestWithEmptyScopeEmptyRole() {
        def scopeClaim = "custom_scope"
        def roleClaim = "custom_role"
        def accessTokenString = "an_access_token"
        def converter = new ConfigurableAccessTokenConverter(scopeClaim, roleClaim)
        def initialClaimMap = [
                custom_scope: "",
                custom_role: ""
        ]
        def accessToken = converter.extractAccessToken(accessTokenString, initialClaimMap)
        assertThat accessToken.value, equalTo(accessTokenString)
        assertThat accessToken.scope, hasSize(0)
        assertThat accessToken.additionalInformation.get(UserAuthenticationConverter.AUTHORITIES), nullValue()
    }

    @Test
    void extractAuthenticationTestWithNullScopeNullRole() {
        def scopeClaim = "custom_scope"
        def roleClaim = "custom_role"
        def converter = new ConfigurableAccessTokenConverter(scopeClaim, roleClaim)
        def initialClaimMap = [
                custom_scope: null,
                custom_role: null
        ]
        def auth = converter.extractAuthentication(initialClaimMap)
        assertThat auth.authorities, hasSize(0)
        assertThat auth.getOAuth2Request().scope, hasSize(0)
    }

    @Test
    void extractAuthenticationTestWithScopeArray() {
        def scopeClaim = "custom_scope"
        def roleClaim = "custom_role"
        def converter = new ConfigurableAccessTokenConverter(scopeClaim, roleClaim)
        def initialClaimMap = [
                custom_scope: ["my_custom_scope", "as_an_array"],
                custom_role: ["one_role", "two_role", "red_role", "blue_role"]
        ]
        def auth = converter.extractAuthentication(initialClaimMap)
        assertThat auth.getOAuth2Request().scope, allOf(containsInAnyOrder("my_custom_scope", "as_an_array"), hasSize(2))
        assertThat auth.authorities, allOf(
                                        containsInAnyOrder(
                                            new SimpleGrantedAuthority("one_role"),
                                            new SimpleGrantedAuthority("two_role"),
                                            new SimpleGrantedAuthority("red_role"),
                                            new SimpleGrantedAuthority("blue_role")),
                                        hasSize(4))
        assertThat auth.getUserAuthentication(), nullValue()
    }

    @Test
    void extractSubject() {
        def scopeClaim = "custom_scope"
        def roleClaim = "custom_role"
        def email = "joe.coder@example.com"
        def converter = new ConfigurableAccessTokenConverter(scopeClaim, roleClaim)
        def initialClaimMap = [
                sub: email,
                custom_scope: ["my_custom_scope", "as_an_array"],
                custom_role: ["one_role", "two_role", "red_role", "blue_role"]
        ]
        def auth = converter.extractAuthentication(initialClaimMap)
        assertThat auth.getUserAuthentication().name, equalTo(email)
    }
}
