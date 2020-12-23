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
import org.mockserver.integration.ClientAndServer
import org.mockserver.model.Cookie
import org.mockserver.model.Header
import org.mockserver.model.HttpRequest
import org.mockserver.model.HttpResponse
import org.mockserver.verify.VerificationTimes
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.HttpMethod
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.web.client.RestTemplate
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

import static java.util.Collections.singletonList
import static java.util.Collections.singletonMap
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class OktaOAuth2AutoConfigRestTemplateTest {
    private static final String LOCALHOST = "localhost"
    private static final int PORT = 7000
    private static final ClientAndServer SERVER_MOCK = buildServerMock(PORT)

    @AfterClass
    static void stop() {
        SERVER_MOCK.stop()
    }

    @Test
    void testRestTemplate() {
        String sessionId = UUID.randomUUID().toString()
        RestTemplate restTemplate = new OktaOAuth2AutoConfig().restTemplate(new OktaOAuth2Properties(null))
        def headers = new HttpHeaders(singletonMap("Cookie", "sessionId=" + sessionId))
        ResponseEntity<OAuth2AccessTokenResponse> response = restTemplate
            .exchange("http://${LOCALHOST}:${PORT}", HttpMethod.GET, new HttpEntity<String>(headers), OAuth2AccessTokenResponse)

        verify(response, sessionId)
    }

    @Test
    void testRestTemplateWithProxy() {
        String sessionId = UUID.randomUUID().toString()
        OktaOAuth2Properties properties = new OktaOAuth2Properties(null)
        properties.setProxyHost(LOCALHOST)
        properties.setProxyPort(PORT)
        properties.setProxyUser("foo")
        properties.setProxyPassword("bar")

        RestTemplate restTemplate = new OktaOAuth2AutoConfig().restTemplate(properties)
        def headers = new HttpHeaders(singletonMap("Cookie", "sessionId=" + sessionId))
        ResponseEntity<OAuth2AccessTokenResponse> response = restTemplate
            .exchange("http://base_url.com", HttpMethod.GET, new HttpEntity<String>(headers), OAuth2AccessTokenResponse)
        verify(response, sessionId)
        assertThat "Wrong user", Authenticator.theAuthenticator.getAt("proxyUser"), is("foo")
        assertThat "Wrong password", Authenticator.theAuthenticator.getAt("proxyPassword").toString(), is("bar")

    }

    private static void verify(ResponseEntity<OAuth2AccessTokenResponse> response, String sessionId) {
        assertThat "Wrong status", response.getStatusCode(), is(HttpStatus.OK)
        assertThat "Wrong content-type", response.getHeaders().get("Content-Type"), is(singletonList("application/json"))
        assertThat "Wrong body", response.getBody().getAccessToken().getTokenValue(), is("AccessTokenValue")

        SERVER_MOCK.verify(
            HttpRequest.request().withCookies(Cookie.cookie("sessionId", sessionId)),
            VerificationTimes.once()
        )
    }

    private static ClientAndServer buildServerMock(int port) {
        ClientAndServer serverMock = ClientAndServer.startClientAndServer(port)
        serverMock
            .when(
                HttpRequest.request()
                    .withMethod("GET")
            )
            .respond(
                HttpResponse.response()
                    .withStatusCode(200)
                    .withHeaders(new Header("Content-Type", "application/json"))
                    .withBody(""" { "access_token" : "AccessTokenValue", "token_type" : "bearer" } """)
            )
        return serverMock
    }
}
