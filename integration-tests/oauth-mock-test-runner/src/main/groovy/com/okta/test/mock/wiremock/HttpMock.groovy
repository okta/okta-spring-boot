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
package com.okta.test.mock.wiremock

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.ClasspathFileSource
import com.github.tomakehurst.wiremock.common.FileSource
import com.github.tomakehurst.wiremock.extension.Parameters
import com.github.tomakehurst.wiremock.extension.ResponseTransformer
import com.github.tomakehurst.wiremock.http.Request
import com.github.tomakehurst.wiremock.http.Response
import groovy.text.StreamingTemplateEngine
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass
import org.apache.commons.codec.binary.Base64
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.regex.Pattern
import java.util.logging.Logger

import static TestUtils.toIntegerBytes
import static com.github.tomakehurst.wiremock.client.WireMock.*
import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.is
import static org.hamcrest.text.MatchesPattern.matchesPattern
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

abstract class HttpMock {

    private WireMockServer wireMockServer
    private int port
    String pubKeyE
    String pubKeyN
    String accessTokenJwt
    String wrongKeyIdAccessTokenJwt
    String wrongScopeAccessTokenJwt
    String wrongAudienceAccessTokenJwt
    String invalidSignatureAccessTokenJwt
    String idTokenjwt
    String scenario
    Logger logger = Logger.getLogger("")

    Map getBindingMap() {
        return [
                baseUrl: getBaseUrl(),
                accessTokenJwt: accessTokenJwt,
                baseUrl: getBaseUrl(),
                pubKeyE: pubKeyE,
                pubKeyN: pubKeyN,
                idTokenjwt: idTokenjwt
        ]
    }

    void setScenario(String scenario) {
        this.scenario = scenario
    }

    void startMockServer() {
        if (wireMockServer == null) {
            setupJwts()
            wireMockServer = new WireMockServer(wireMockConfig()
                    .port(getMockPort())
                    .fileSource(new ClasspathFileSource("stubs"))
                    .extensions(new GStringTransformer(getBindingMap()))
            )
            
            configureHttpMock(wireMockServer)
            wireMockServer.start()
        }
    }

    @AfterClass
    void stopMockServer() {
        if (wireMockServer != null) {
            wireMockServer.stop()
        }
    }

    int getMockPort() {
        if (port == 0) {
            port = doGetMockPort()
        }
        return port
    }

    abstract int doGetMockPort()

    String getBaseUrl() {
        return "http://localhost:${getMockPort()}"
    }

    void setupJwts() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(4096)
        KeyPair invalidKeyPair = keyPairGenerator.generateKeyPair()
        KeyPair keyPair = keyPairGenerator.generateKeyPair()

        pubKeyE = Base64.encodeBase64URLSafeString(TestUtils.toIntegerBytes(keyPair.publicKey.getPublicExponent()))
        pubKeyN = Base64.encodeBase64URLSafeString(TestUtils.toIntegerBytes(keyPair.publicKey.getModulus()))

        Instant now = Instant.now()
        accessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://default")
                .claim("scp", ["profile", "openid", "email"])
                .claim("groups", ["Everyone", "Test-Group"])
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
                .claim("groups", ["Everyone", "Test-Group"])
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
                .claim("groups", ["Everyone", "Test-Group"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                    .setKeyId('TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()

        invalidSignatureAccessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://default")
                .claim("scp", ["profile", "openid", "email"])
                .claim("groups", ["Everyone", "Test-Group"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                .setKeyId('TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, invalidKeyPair.private)
                .compact()
                
        wrongAudienceAccessTokenJwt =  Jwts.builder()
                .setSubject("joe.coder@example.com")
                .setAudience("api://wrong-default")
                .claim("scp", ["profile", "openid", "email"])
                .claim("groups", ["Everyone", "Test-Group"])
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
    }

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
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_invalidSignatureAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("token.json")
                            .withTransformer("gstring-template", "accessTokenJwt", invalidSignatureAccessTokenJwt)))

        wireMockServer.stubFor(
                get(urlPathEqualTo("/oauth2/default/v1/keys"))
                    .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBodyFile("keys.json")
                        .withTransformers("gstring-template")))

        switch (scenario) {
            case "code-flow-local-validation":
                wireMockServer.stubFor(
                    post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withHeader("Content-Type", equalTo("application/x-www-form-urlencoded"))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Flogin") +".*"))
                        .withRequestBody(containing("client_id=OOICU812"))
                        .withRequestBody(containing("client_secret=VERY_SECRET"))
                        .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json;charset=UTF-8")
                            .withBodyFile("token.json")
                            .withTransformers("gstring-template")))
                break

            case "code-flow-remote-validation":
                wireMockServer.stubFor(
                    post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withHeader("Content-Type", equalTo("application/x-www-form-urlencoded"))
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
                break 

            case "implicit-flow-remote-validation":
                wireMockServer.stubFor(
                    get(urlPathEqualTo("/oauth2/default/v1/userinfo"))
                        .withHeader("Authorization", containing("Bearer some.random.jwt"))
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBodyFile("userinfo-remote-access-token.json")))
                break          
        }      
    }
}

class GStringTransformer extends ResponseTransformer {

    private final Map binding

    GStringTransformer(Map binding) {
        this.binding = binding
    }

    @Override
    boolean applyGlobally() {
        return false
    }

    @Override
    Response transform(Request request, Response response, FileSource files, Parameters parameters) {
        Map params = (parameters == null) ? binding : binding + parameters
        return Response.Builder
                .like(response)
                .body(new StreamingTemplateEngine().createTemplate(response.bodyAsString).make(params).toString())
                .build()
    }

    @Override
    String getName() {
        return "gstring-template"
    }
}