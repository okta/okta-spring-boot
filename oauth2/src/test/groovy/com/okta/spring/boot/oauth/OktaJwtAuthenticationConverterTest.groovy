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

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.testng.annotations.Test

import java.time.Instant

import static org.hamcrest.Matchers.hasItems
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasSize

class OktaJwtAuthenticationConverterTest {

    @Test
    void extractAuthorities_simpleTest() {

        // these maps must not be empty
        def jwt = new Jwt("foo", Instant.now(), Instant.now().plusMillis(1000L), [simple: "value"], [
                scp: ["one", "two", "three"],
                myGroups: ["g1", "g2"]
        ])

        def authorities = new OktaJwtAuthenticationConverter("myGroups").convert(jwt).getAuthorities()
        assertThat authorities, hasItems(
                new SimpleGrantedAuthority("SCOPE_one"),
                new SimpleGrantedAuthority("SCOPE_two"),
                new SimpleGrantedAuthority("SCOPE_three"),
                new SimpleGrantedAuthority("g1"),
                new SimpleGrantedAuthority("g2"))
    }

    @Test
    void extractAuthorities_customClaimNameTest() {

        // these maps must not be empty
        def jwt = new Jwt("foo", Instant.now(), Instant.now().plusMillis(1000L), [simple: "value"], [
            permissions: ["one", "two", "three"],
            myGroups   : ["g1", "g2"]
        ])

        def properties = new OktaOAuth2Properties(null)
        properties.setGroupsClaim("myGroups")
        properties.setAuthoritiesClaimName("permissions")

        def authorities = new OktaJwtAuthenticationConverter(properties).convert(jwt).getAuthorities()
        assertThat authorities, hasItems(
            new SimpleGrantedAuthority("SCOPE_one"),
            new SimpleGrantedAuthority("SCOPE_two"),
            new SimpleGrantedAuthority("SCOPE_three"),
            new SimpleGrantedAuthority("g1"),
            new SimpleGrantedAuthority("g2"))
    }

    @Test
    void extractAuthorities_emptyTest() {
        def jwt = new Jwt("foo", Instant.now(), Instant.now().plusMillis(1000L), [simple: "value"], [simple: "value"]) // these maps must not be empty

        def authorities = new OktaJwtAuthenticationConverter("myGroups").convert(jwt).getAuthorities()
        // In Spring Security 7.x, JwtGrantedAuthoritiesConverter includes a default authority based on the principal name
        // when no scopes are present. We verify that no custom group-based authorities were added.
        assertThat authorities, hasSize(1)
    }
}