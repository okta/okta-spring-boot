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
package com.okta.test.mock.tests

import com.github.tomakehurst.wiremock.WireMockServer
import com.okta.test.mock.Scenario
import com.okta.test.mock.application.ApplicationTestRunner
import io.restassured.http.ContentType
import io.restassured.response.ExtractableResponse
import org.hamcrest.Matchers
import org.testng.annotations.Test

import java.util.regex.Pattern

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.is
import static org.hamcrest.text.MatchesPattern.matchesPattern

@Scenario("code-flow-remote-validation")
class CodeFlowRemoteValidationIT extends ApplicationTestRunner {

    @Override
    void configureHttpMock(WireMockServer wireMockServer) {
        wireMockServer.stubFor(
                get("/oauth2/default/.well-known/openid-configuration")
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json")
                            .withBodyFile("discovery.json")
                            .withTransformers("gstring-template")))

        wireMockServer.stubFor(
                get(urlPathEqualTo("/oauth2/default/v1/authorize"))
                        .withQueryParam("client_id", matching("OOICU812"))
                        .withQueryParam("redirect_uri", matching(Pattern.quote("http://localhost:")+ "\\d+/login"))
                        .withQueryParam("response_type", matching("code"))
                        .withQueryParam("scope", matching("profile email openid"))
                        .withQueryParam("state", matching(".{6}"))
                        .willReturn(aResponse()
                            .withBody("<html>fake_login_page<html/>")))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("remote-validation-token.json")))

        wireMockServer.stubFor(
                get(urlPathEqualTo("/oauth2/default/v1/userinfo"))
                        .withHeader("Authorization", containing("Bearer accessTokenJwt"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("userinfo.json")))
    }

    @Test
    void redirectToLogin() {
        given()
            .redirects()
                .follow(false)
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}/")
        .then()
            .statusCode(302)
            .header("Location", is("http://localhost:${applicationPort}/login".toString()))
    }

    @Test
    ExtractableResponse redirectToRemoteLogin() {

        String expectedRedirect = Pattern.quote(
                "http://localhost:${doGetMockPort()}/oauth2/default/v1/authorize" +
                "?client_id=OOICU812" +
                "&redirect_uri=http://localhost:${applicationPort}/login" +
                "&response_type=code" +
                "&scope=profile%20email%20openid" +
                "&state=")+".{6}"

        return given()
            .redirects()
                .follow(false)
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}/login")
        .then()
            .statusCode(302)
            .header("Location", org.hamcrest.text.MatchesPattern.matchesPattern(expectedRedirect))
        .extract()
    }

    @Test
    void followRedirect() {
        given()
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}/")
        .then()
            .statusCode(200)
            .body(Matchers.equalTo("<html>fake_login_page<html/>"))
    }

    @Test
    void respondWithCode() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String code = "TEST_CODE"
        String requestUrl = "http://localhost:${applicationPort}/login?code=${code}&state=${state}"

        ExtractableResponse response2 = given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
                .follow(false)
        .when()
            .get(requestUrl)
        .then()
            .statusCode(302)
                .header("Location", Matchers.equalTo("http://localhost:${applicationPort}/".toString()))
        .extract()

        given()
            .accept(ContentType.JSON)
            .cookies(response2.cookies())
            .redirects()
                .follow(false)
        .when()
            .get("http://localhost:${applicationPort}/")
        .then()
            .body(Matchers.equalTo("The message of the day is boring: joe.coder@example.com"))

    }

}