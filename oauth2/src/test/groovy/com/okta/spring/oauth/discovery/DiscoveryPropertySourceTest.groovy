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
package com.okta.spring.oauth.discovery

import org.springframework.core.env.Environment
import org.testng.annotations.Test

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat
import static org.mockito.Mockito.*

/**
 * Tests for {@link DiscoveryPropertySource}.
 *
 * @since 0.3.0
 */
class DiscoveryPropertySourceTest {

    /**
     * Validates that when disabled, discovery will NOT throw an exception or attempt to make a remote connection.
     */
    @Test
    void disabledDiscoveryTest() {
        Environment env = mock(Environment)
        when(env.getProperty("okta.oauth2.discoveryDisabled")).thenReturn("true")
        DiscoveryPropertySource propertySource = new DiscoveryPropertySource(env)

        assertThat propertySource.containsProperty("security.oauth2.client.accessTokenUri"), equalTo(false)
        assertThat propertySource.getProperty("security.oauth2.client.userAuthorizationUri"), nullValue()
    }

    @Test
    void nullMetadataTest() {

        Environment env = mock(Environment)
        when(env.containsProperty("okta.oauth2.issuer")).thenReturn(true)
        when(env.getRequiredProperty("okta.oauth2.issuer")).thenReturn("https://okta.example.com/issuer")

        OidcDiscoveryClient discoveryClient = mock(OidcDiscoveryClient)
        when(discoveryClient.discover()).thenReturn(null)

        DiscoveryPropertySource propertySource = new DiscoveryPropertySource(env) {
            @Override
            OidcDiscoveryClient createDiscoveryClient(String issuerUrl) {
                return discoveryClient
            }
        }
        assertThat propertySource.getProperty("security.oauth2.client.userAuthorizationUri"), nullValue()
    }

    @Test
    void nullMetadataValueTest() {

        Environment env = mock(Environment)
        when(env.containsProperty("okta.oauth2.issuer")).thenReturn(true)
        when(env.getRequiredProperty("okta.oauth2.issuer")).thenReturn("https://okta.example.com/issuer")

        OidcDiscoveryMetadata metadata = mock(OidcDiscoveryMetadata)
        when(metadata.getTokenEndpoint()).thenReturn(null)

        OidcDiscoveryClient discoveryClient = mock(OidcDiscoveryClient)
        when(discoveryClient.discover()).thenReturn(metadata)

        DiscoveryPropertySource propertySource = new DiscoveryPropertySource(env) {
            @Override
            OidcDiscoveryClient createDiscoveryClient(String issuerUrl) {
                return discoveryClient
            }
        }
        assertThat propertySource.getProperty("security.oauth2.client.accessTokenUri"), nullValue()
    }

    @Test
    void metadataValuesTest() {

        Environment env = mock(Environment)
        when(env.containsProperty("okta.oauth2.issuer")).thenReturn(true)
        when(env.getRequiredProperty("okta.oauth2.issuer")).thenReturn("https://okta.example.com/issuer")

        OidcDiscoveryMetadata metadata = mock(OidcDiscoveryMetadata)
        when(metadata.getTokenEndpoint()).thenReturn("tokenEndpoint")
        when(metadata.getAuthorizationEndpoint()).thenReturn("authorizationEndpoint")
        when(metadata.getUserinfoEndpoint()).thenReturn("userinfoEndpoint")
        when(metadata.getJwksUri()).thenReturn("jwksUri")
        when(metadata.getIntrospectionEndpoint()).thenReturn("introspectionEndpoint")

        OidcDiscoveryClient discoveryClient = mock(OidcDiscoveryClient)
        when(discoveryClient.discover()).thenReturn(metadata)

        DiscoveryPropertySource propertySource = new DiscoveryPropertySource(env) {
            @Override
            OidcDiscoveryClient createDiscoveryClient(String issuerUrl) {
                return discoveryClient
            }
        }
        assertThat propertySource.getProperty("discovery.token-endpoint"), equalTo("tokenEndpoint")
        assertThat propertySource.getProperty("discovery.authorization-endpoint"), equalTo("authorizationEndpoint")
        assertThat propertySource.getProperty("discovery.userinfo-endpoint"), equalTo("userinfoEndpoint")
        assertThat propertySource.getProperty("discovery.jwks-uri"), equalTo("jwksUri")
        assertThat propertySource.getProperty("discovery.introspection-endpoint"), equalTo("introspectionEndpoint")
    }
}
