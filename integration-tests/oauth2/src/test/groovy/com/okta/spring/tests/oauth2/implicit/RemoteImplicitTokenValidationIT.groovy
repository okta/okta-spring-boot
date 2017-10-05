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
import com.okta.spring.tests.wiremock.HttpMock
import io.restassured.http.ContentType
import org.hamcrest.Matchers
import org.springframework.boot.context.embedded.LocalServerPort
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests
import org.testng.IHookCallBack
import org.testng.ITestResult
import org.testng.annotations.Test

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.startsWith

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
                classes = [BasicImplicitFlowApplication],
                properties = ["okta.oauth2.issuer=http://localhost:9985/oauth2/default",
                              "okta.oauth2.clientId=OOICU812",
                              "server.session.trackingModes=cookie",
                              "okta.oauth2.localTokenValidation=false"])
class RemoteImplicitTokenValidationIT extends AbstractTestNGSpringContextTests implements HttpMock {

    @LocalServerPort
    int applicationPort

    RemoteImplicitTokenValidationIT() {
        startMockServer()
    }

    @Override
    void run(IHookCallBack callBack, ITestResult testResult) {

        super.run(callBack, testResult)
    }

    @Override
    int doGetMockPort() {
        return 9985
    }

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
    void noToken401() {
        given()
            .redirects()
            .follow(false)
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}/")
        .then()
            .statusCode(401)
            .header("WWW-Authenticate", startsWith("Bearer realm="))
    }

    @Test
    void scopeAccessTest() {

        given()
            .header("Authorization", "Bearer some.random.jwt")
            .redirects()
                .follow(false)
        .when()
            .get("http://localhost:${applicationPort}/")
        .then()
            .statusCode(403)
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