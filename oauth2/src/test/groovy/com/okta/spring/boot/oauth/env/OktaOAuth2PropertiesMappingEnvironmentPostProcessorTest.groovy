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
package com.okta.spring.boot.oauth.env

import org.springframework.core.env.Environment
import org.springframework.core.env.MapPropertySource
import org.springframework.mock.env.MockEnvironment
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.nullValue

class OktaOAuth2PropertiesMappingEnvironmentPostProcessorTest {

    final static String CLIENT_ID = "spring.security.oauth2.client.registration.okta.client-id"
    final static String CLIENT_SECRET = "spring.security.oauth2.client.registration.okta.client-secret"
    final static String SCOPE = "spring.security.oauth2.client.registration.okta.scope"
    final static String ISSUER = "spring.security.oauth2.resourceserver.jwt.issuer-uri"
    final static String RS_KEYS_URI = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri"
    final static String RS_CLIENT_ID = "spring.security.oauth2.resourceserver.opaque-token.client-id"
    final static String RS_CLIENT_SECRET = "spring.security.oauth2.resourceserver.opaque-token.client-secret"
    final static String RS_INTROSPECTION_URI = "spring.security.oauth2.resourceserver.opaque-token.introspection-uri"
    final static String AUTHZ_URI = "spring.security.oauth2.client.provider.okta.authorization-uri"
    final static String TOKEN_URI = "spring.security.oauth2.client.provider.okta.token-uri"
    final static String USER_INFO_URI = "spring.security.oauth2.client.provider.okta.user-info-uri"
    final static String PROVIDER_KEYS_URI = "spring.security.oauth2.client.provider.okta.jwk-set-uri"

    @Test
    void happyPath() {
        def environment = buildAndProcessEnvironment([
                "okta.oauth2.client-id": "test-client-id",
                "okta.oauth2.client-secret": "test-client-secret",
                "okta.oauth2.issuer": "https://issuer.example.com/foobar",
                "okta.oauth2.scopes": ["one", "two", "three"],
        ])

        assertThat environment.getProperty(CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(CLIENT_SECRET), is("test-client-secret")
        assertThat environment.getProperty(SCOPE, Set), is(["one", "two", "three"] as Set)
        assertThat environment.getProperty(ISSUER), is("https://issuer.example.com/foobar")
        assertThat environment.getProperty(RS_KEYS_URI),is("https://issuer.example.com/foobar/v1/keys")
        assertThat environment.getProperty(AUTHZ_URI), is("https://issuer.example.com/foobar/v1/authorize")
        assertThat environment.getProperty(TOKEN_URI), is("https://issuer.example.com/foobar/v1/token")
        assertThat environment.getProperty(USER_INFO_URI), is("https://issuer.example.com/foobar/v1/userinfo")
        assertThat environment.getProperty(PROVIDER_KEYS_URI), is("https://issuer.example.com/foobar/v1/keys")
        assertThat environment.getProperty(RS_CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(RS_CLIENT_SECRET), is("test-client-secret")
        assertThat environment.getProperty(RS_INTROSPECTION_URI), is("https://issuer.example.com/foobar/v1/introspect")
    }

    @Test
    void noPropertiesTest() {
        def environment = buildAndProcessEnvironment(Collections.emptyMap())

        assertThat environment.getProperty(CLIENT_ID), nullValue()
        assertThat environment.getProperty(CLIENT_SECRET), nullValue()
        assertThat environment.getProperty(SCOPE, Set), nullValue()
        assertThat environment.getProperty(ISSUER), nullValue()
        assertThat environment.getProperty(RS_KEYS_URI), nullValue()
        assertThat environment.getProperty(AUTHZ_URI), nullValue()
        assertThat environment.getProperty(TOKEN_URI), nullValue()
        assertThat environment.getProperty(USER_INFO_URI), nullValue()
        assertThat environment.getProperty(PROVIDER_KEYS_URI), nullValue()
        assertThat environment.getProperty(RS_CLIENT_ID), nullValue()
        assertThat environment.getProperty(RS_CLIENT_SECRET), nullValue()
        assertThat environment.getProperty(RS_INTROSPECTION_URI), nullValue()
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    void missingClientSecret() {
        def environment = buildAndProcessEnvironment([
            "okta.oauth2.client-id": "test-client-id",
            "okta.oauth2.issuer": "https://issuer.example.com/foobar",
            "okta.oauth2.scopes": ["one", "two", "three"],
        ])

        assertThat environment.getProperty(CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(CLIENT_SECRET), nullValue()
        assertThat environment.getProperty(SCOPE, Set), is(["one", "two", "three"] as Set)
        assertThat environment.getProperty(ISSUER), is("https://issuer.example.com/foobar")
        assertThat environment.getProperty(RS_KEYS_URI),is("https://issuer.example.com/foobar/v1/keys")
        assertThat environment.getProperty(AUTHZ_URI), is("https://issuer.example.com/foobar/v1/authorize")
        assertThat environment.getProperty(TOKEN_URI), is("https://issuer.example.com/foobar/v1/token")
        assertThat environment.getProperty(USER_INFO_URI), is("https://issuer.example.com/foobar/v1/userinfo")
        assertThat environment.getProperty(PROVIDER_KEYS_URI), is("https://issuer.example.com/foobar/v1/keys")
        assertThat environment.getProperty(RS_CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(RS_INTROSPECTION_URI), is("https://issuer.example.com/foobar/v1/introspect")
        assertThat environment.getProperty(RS_CLIENT_SECRET), nullValue()
    }

    private Environment buildAndProcessEnvironment(Map<String, Object> properties) {
        def environment = new MockEnvironment()
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties))

        def underTest = new OktaOAuth2PropertiesMappingEnvironmentPostProcessor()
        underTest.postProcessEnvironment(environment, null)

        return environment
    }

}