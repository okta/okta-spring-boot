package com.okta.spring.boot.oauth

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

        def authorities = new OktaJwtAuthenticationConverter("myGroups").extractAuthorities(jwt)
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

        def authorities = new OktaJwtAuthenticationConverter("myGroups").extractAuthorities(jwt)
        assertThat authorities, hasSize(0)
    }
}