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

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.okta.spring.boot.oauth.HttpMock
import org.springframework.core.env.Environment
import org.springframework.core.env.MapPropertySource
import org.springframework.mock.env.MockEnvironment
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.nullValue

class OktaOAuth2PropertiesMappingEnvironmentPostProcessorTest implements HttpMock {

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

    @Override
    void configureHttpMock(WireMockServer wireMockServer) {
        String orgIssuer = "${mockBaseUrl()}foobar/"
        wireMockServer.stubFor(
            WireMock.get("/foobar/.well-known/openid-configuration")
                .willReturn(WireMock.aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(""" {
                        "issuer": "${orgIssuer}",
                        "subject_types_supported": ["public"],
                        "end_session_endpoint":"${orgIssuer}oauth2/v1/logout",
                        "authorization_endpoint":"${orgIssuer}oauth2/v1/authorize",
                        "token_endpoint":"${orgIssuer}oauth2/v1/token",
                        "userinfo_endpoint":"${orgIssuer}oauth2/v1/userinfo",
                        "registration_endpoint":"${orgIssuer}oauth2/v1/clients",
                        "jwks_uri":"${orgIssuer}oauth2/v1/keys",
                        "introspection_endpoint":"${orgIssuer}oauth2/v1/introspect"
                    }
                    """)))
    }

    @Test
    void happyPath() {
        String orgIssuer = "${mockBaseUrl()}foobar/"
        def environment = buildAndProcessEnvironment([
                "okta.oauth2.client-id": "test-client-id",
                "okta.oauth2.client-secret": "test-client-secret",
                "okta.oauth2.issuer": orgIssuer,
                "okta.oauth2.scopes": ["one", "two", "three"],
        ])


        assertThat environment.getProperty(CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(CLIENT_SECRET), is("test-client-secret")
        assertThat environment.getProperty(SCOPE, Set), is(["one", "two", "three"] as Set)
        assertThat environment.getProperty(ISSUER), is(orgIssuer)
        assertThat environment.getProperty(RS_KEYS_URI), is("${orgIssuer}oauth2/v1/keys" as String)
        assertThat environment.getProperty(AUTHZ_URI), is("${orgIssuer}oauth2/v1/authorize" as String)
        assertThat environment.getProperty(TOKEN_URI), is("${orgIssuer}oauth2/v1/token" as String)
        assertThat environment.getProperty(USER_INFO_URI), is("${orgIssuer}oauth2/v1/userinfo" as String)
        assertThat environment.getProperty(PROVIDER_KEYS_URI), is("${orgIssuer}oauth2/v1/keys" as String)
        assertThat environment.getProperty(RS_CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(RS_CLIENT_SECRET), is("test-client-secret")
        assertThat environment.getProperty(RS_INTROSPECTION_URI), is("${orgIssuer}oauth2/v1/introspect" as String)
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

    @Test
    void missingClientSecret() {
        String orgIssuer = "${mockBaseUrl()}foobar/"
        def environment = buildAndProcessEnvironment([
            "okta.oauth2.client-id": "test-client-id",
            "okta.oauth2.issuer": orgIssuer,
            "okta.oauth2.scopes": ["one", "two", "three"],
        ])

        assertThat environment.getProperty(CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(CLIENT_SECRET), nullValue()
        assertThat environment.getProperty(SCOPE, Set), is(["one", "two", "three"] as Set)
        assertThat environment.getProperty(ISSUER), is(orgIssuer)
        assertThat environment.getProperty(RS_KEYS_URI),is("${orgIssuer}oauth2/v1/keys" as String)
        assertThat environment.getProperty(AUTHZ_URI), is("${orgIssuer}oauth2/v1/authorize" as String)
        assertThat environment.getProperty(TOKEN_URI), is("${orgIssuer}oauth2/v1/token" as String)
        assertThat environment.getProperty(USER_INFO_URI), is("${orgIssuer}oauth2/v1/userinfo" as String)
        assertThat environment.getProperty(PROVIDER_KEYS_URI), is("${orgIssuer}oauth2/v1/keys" as String)
        assertThat environment.getProperty(RS_CLIENT_ID), nullValue()
        assertThat environment.getProperty(RS_INTROSPECTION_URI), nullValue()
        assertThat environment.getProperty(RS_CLIENT_SECRET), nullValue()
    }

    @Test
    void testOauth2Path() {
        def environment = buildAndProcessEnvironment([
            "okta.oauth2.client-id": "test-client-id",
            "okta.oauth2.issuer"   : "https://issuer.example.com/oauth2/default",
            "okta.oauth2.scopes"   : ["one", "two", "three"],
        ])

        assertThat environment.getProperty(CLIENT_ID), is("test-client-id")
        assertThat environment.getProperty(CLIENT_SECRET), nullValue()
        assertThat environment.getProperty(SCOPE, Set), is(["one", "two", "three"] as Set)
        assertThat environment.getProperty(ISSUER), is("https://issuer.example.com/oauth2/default")
        assertThat environment.getProperty(RS_KEYS_URI), is("https://issuer.example.com/oauth2/default/v1/keys")
        assertThat environment.getProperty(AUTHZ_URI), is("https://issuer.example.com/oauth2/default/v1/authorize")
        assertThat environment.getProperty(TOKEN_URI), is("https://issuer.example.com/oauth2/default/v1/token")
        assertThat environment.getProperty(USER_INFO_URI), is("https://issuer.example.com/oauth2/default/v1/userinfo")
        assertThat environment.getProperty(PROVIDER_KEYS_URI), is("https://issuer.example.com/oauth2/default/v1/keys")
        assertThat environment.getProperty(RS_CLIENT_ID), nullValue()
        assertThat environment.getProperty(RS_INTROSPECTION_URI), nullValue()
        assertThat environment.getProperty(RS_CLIENT_SECRET), nullValue()
    }

    private static Environment buildAndProcessEnvironment(Map<String, Object> properties) {
        def environment = new MockEnvironment()
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties))

        def underTest = new OktaOAuth2PropertiesMappingEnvironmentPostProcessor()
        underTest.postProcessEnvironment(environment, null)

        return environment
    }

}