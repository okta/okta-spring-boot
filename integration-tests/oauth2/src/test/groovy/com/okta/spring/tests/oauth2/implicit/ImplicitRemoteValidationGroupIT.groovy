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
package com.okta.spring.tests.oauth2.implicit

import com.github.tomakehurst.wiremock.WireMockServer
import com.okta.test.mock.Scenario
import com.okta.test.mock.application.ApplicationTestRunner
import org.hamcrest.Matchers
import org.testng.annotations.Test

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.containing
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import static io.restassured.RestAssured.given

@Scenario("implicit-flow-remote-validation")
class ImplicitRemoteValidationGroupIT extends ApplicationTestRunner {

    @Override
    void configureHttpMock(WireMockServer wireMockServer) {
        wireMockServer.stubFor(
                get("/oauth2/default/.well-known/openid-configuration")
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                            .withBodyFile("discovery.json")
                            .withTransformers("gstring-template")))

        wireMockServer.stubFor(
                get(urlPathEqualTo("/oauth2/default/v1/keys"))
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("keys.json")
                            .withTransformers("gstring-template")))

        wireMockServer.stubFor(
                get(urlPathEqualTo("/oauth2/default/v1/userinfo"))
                        .withHeader("Authorization", containing("Bearer some.random.jwt"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("userinfo-remote-access-token.json")))
    }

    @Test
    void groupAccessTest() {

        given()
            .header("Authorization", "Bearer some.random.jwt")
            .redirects()
                .follow(false)
        .when()
            .get("http://localhost:${applicationPort}/everyone")
        .then()
            .body(Matchers.equalTo("Everyone has Access: joe.coder@example.com"))
    }
}