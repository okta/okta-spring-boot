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

import com.okta.test.mock.Scenario
import com.okta.test.mock.application.ApplicationTestRunner
import io.restassured.http.ContentType
import io.restassured.response.ExtractableResponse
import org.hamcrest.Matchers
import org.testng.annotations.Test
import java.util.regex.Pattern

import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.is
import static org.hamcrest.text.MatchesPattern.matchesPattern

@Scenario("code-flow-local-validation")
class CodeFlowLocalValidationIT extends ApplicationTestRunner {
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
            .header("Location", is("http://localhost:${applicationPort}/authorization-code/callback".toString()))
    }

    @Test
    ExtractableResponse redirectToRemoteLogin() {
        String expectedRedirect = Pattern.quote(
                "http://localhost:${doGetMockPort()}/oauth2/default/v1/authorize" +
                "?client_id=OOICU812" +
                "&redirect_uri=http://localhost:${applicationPort}/authorization-code/callback" +
                "&response_type=code" +
                "&scope=profile%20email%20openid" +
                "&state=")+".{6}"

        return given()
            .redirects()
                .follow(false)
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}/authorization-code/callback")
        .then()
            .statusCode(302)
            .header("Location", matchesPattern(expectedRedirect))
        .extract()
    }

    @Test
    void followRedirect() {
        given()
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}/authorization-code/callback")
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
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?code=${code}&state=${state}"

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

    @Test
    void wrongStateTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1) + "wrong"
        String code = "TEST_CODE"
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?code=${code}&state=${state}"

        ExtractableResponse response2 = given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
                .follow(false)
        .when()
            .get(requestUrl)
        .then()
            .statusCode(401)
        .extract()
    }

    @Test
    void noAuthCodeTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?state=${state}"

        ExtractableResponse response2 = given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
                .follow(false)
        .when()
            .get(requestUrl)
        .then()
            .statusCode(500)
        .extract()
    }

    @Test
    void invalidSignatureAccessTokenJwtTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String code = "TEST_CODE_invalidSignatureAccessTokenJwt"
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?code=${code}&state=${state}"

        given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
                .follow(false)
        .when()
            .get(requestUrl)
        .then()
            .statusCode(500)
    }

    @Test
    void wrongKeyIdAccessTokenJwtTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String code = "TEST_CODE_wrongKeyIdAccessTokenJwt"
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?code=${code}&state=${state}"

        given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
                .follow(false)
        .when()
            .get(requestUrl)
        .then()
            .statusCode(401)
    }

    @Test
    void wrongScopeAccessTokenJwtTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String code = "TEST_CODE_wrongScopeAccessTokenJwt"
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?code=${code}&state=${state}"

        ExtractableResponse response2 = given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
               .follow(false)
        .when()
            .get(requestUrl)
        .then().log().everything()
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
        .then().log().everything()
            .statusCode(403)
    }

    @Test
    void wrongAudienceAccessTokenJwtTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String code = "TEST_CODE_wrongAudienceAccessTokenJwt"
        String requestUrl = "http://localhost:${applicationPort}/authorization-code/callback?code=${code}&state=${state}"

        given()
            .accept(ContentType.JSON)
            .cookies(response.cookies())
            .redirects()
                .follow(false)
        .when()
            .get(requestUrl)
        .then()
            .statusCode(401)
    }
}