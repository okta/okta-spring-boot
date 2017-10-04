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
package com.okta.spring.tests.oauth2.code

import com.github.tomakehurst.wiremock.WireMockServer
import com.okta.spring.tests.oauth2.TestUtils
import com.okta.spring.tests.wiremock.HttpMock
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.restassured.http.ContentType
import io.restassured.response.ExtractableResponse
import org.apache.commons.codec.binary.Base64
import org.hamcrest.Matchers
import org.springframework.boot.context.embedded.LocalServerPort
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests
import org.testng.IHookCallBack
import org.testng.ITestResult
import org.testng.annotations.Test

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.regex.Pattern

import static com.okta.spring.tests.oauth2.TestUtils.toIntegerBytes
import static com.github.tomakehurst.wiremock.client.WireMock.*
import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.is
import static org.hamcrest.text.MatchesPattern.matchesPattern

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
                classes = [BasicRedirectCodeFlowApplication],
                properties = ["okta.oauth2.issuer=http://localhost:9988/oauth2/default",
                              "okta.oauth2.clientId=OOICU812",
                              "okta.oauth2.clientSecret=VERY_SECRET",
                              "server.session.trackingModes=cookie"])
class LocalTokenValidationIT extends AbstractTestNGSpringContextTests implements HttpMock {

    @LocalServerPort
    int applicationPort

    String pubKeyE
    String pubKeyN
    String accessTokenJwt
    String wrongKeyIdAccessTokenJwt
    String wrongScopeAccessTokenJwt
    String wrongAudienceAccessTokenJwt
    String idTokenjwt

    LocalTokenValidationIT() {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(4096)
        KeyPair keyPair = keyPairGenerator.generateKeyPair()

        pubKeyE = Base64.encodeBase64URLSafeString(toIntegerBytes(keyPair.publicKey.getPublicExponent()))
        pubKeyN = Base64.encodeBase64URLSafeString(toIntegerBytes(keyPair.publicKey.getModulus()))

        Instant now = Instant.now()
        accessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://default")
                .claim("scp", ["profile", "openid", "email"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                    .setKeyId('TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()

        wrongKeyIdAccessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://default")
                .claim("scp", ["profile", "openid", "email"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                    .setKeyId('WRONG_TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()

        wrongScopeAccessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://default")
                .claim("scp", ["profile", "openid"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                    .setKeyId('TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()

        wrongAudienceAccessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://wrong-default")
                .claim("scp", ["profile", "openid"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                .setKeyId('TEST_PUB_KEY_ID'))
                    .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()

        idTokenjwt =  Jwts.builder()
                .setSubject("a_subject_id")
                .claim("name", "Joe Coder")
                .claim("email", "joe.coder@example.com")
                .claim("preferred_username", "jod.coder@example.com")
                .setAudience("api://default")
                .setIssuer("http://localhost:9988/oauth2/default")
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                    .setKeyId('TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()

        startMockServer()
    }

    @Override
    Map getBindingMap() {
        return [
                accessTokenJwt: accessTokenJwt,
                baseUrl: getBaseUrl(),
                pubKeyE: pubKeyE,
                pubKeyN: pubKeyN,
                idTokenjwt: idTokenjwt
        ]
    }

    @Override
    int doGetMockPort() {
        return 9988
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
                        .withRequestBody(containing("code=TEST_CODE&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("token.json")
                            .withTransformers("gstring-template")))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_wrongKeyIdAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("token.json")
                            .withTransformer("gstring-template", "accessTokenJwt", wrongKeyIdAccessTokenJwt)))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_wrongScopeAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("token.json")
                            .withTransformer("gstring-template", "accessTokenJwt", wrongScopeAccessTokenJwt)))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_wrongAudienceAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("token.json")
                            .withTransformer("gstring-template", "accessTokenJwt", wrongAudienceAccessTokenJwt)))

        wireMockServer.stubFor(
                get(urlPathEqualTo("/oauth2/default/v1/keys"))
                    .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBodyFile("keys.json")
                        .withTransformers("gstring-template")))
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
            .header("Location", matchesPattern(expectedRedirect))
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

    @Test
    void wrongKeyIdAccessTokenJwtTest() {
        ExtractableResponse response = redirectToRemoteLogin()
        String redirectUrl = response.header("Location")
        String state = redirectUrl.substring(redirectUrl.lastIndexOf('=')+1)
        String code = "TEST_CODE_wrongKeyIdAccessTokenJwt"
        String requestUrl = "http://localhost:${applicationPort}/login?code=${code}&state=${state}"

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
        String requestUrl = "http://localhost:${applicationPort}/login?code=${code}&state=${state}"

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
        String requestUrl = "http://localhost:${applicationPort}/login?code=${code}&state=${state}"

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