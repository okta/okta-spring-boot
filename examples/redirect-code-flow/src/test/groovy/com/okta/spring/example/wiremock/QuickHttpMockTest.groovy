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
package com.okta.spring.example.wiremock

import com.github.tomakehurst.wiremock.WireMockServer
import com.okta.spring.oauth.discovery.OidcDiscoveryClient
import com.okta.spring.oauth.discovery.OidcDiscoveryMetadata
import org.testng.annotations.Test

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo

class QuickHttpMockTest implements HttpMock {

    @Test
    void quick() {
        OidcDiscoveryMetadata discoveryMetadata = new OidcDiscoveryClient("${getBaseUrl()}/oauth2/default").discover()
        assertThat discoveryMetadata.jwksUri, equalTo(getBaseUrl()+"/oauth2/default/v1/keys")
    }

    @Override
    void configureHttpMock(WireMockServer wireMockServer) {
        wireMockServer.stubFor(
                get("/oauth2/default/.well-known/openid-configuration")
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("discovery.json")
                        .withTransformers("gstring-template")
                ))
    }
}