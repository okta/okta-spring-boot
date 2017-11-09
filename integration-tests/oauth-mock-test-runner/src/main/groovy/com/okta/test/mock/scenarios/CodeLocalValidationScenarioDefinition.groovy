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
package com.okta.test.mock.scenarios

import com.github.tomakehurst.wiremock.WireMockServer
import com.okta.test.mock.wiremock.TestUtils
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.apache.commons.codec.binary.Base64

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.regex.Pattern

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.containing
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.matching
import static com.github.tomakehurst.wiremock.client.WireMock.post
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;

class CodeLocalValidationScenarioDefinition implements ScenarioDefinition {

    String pubKeyE
    String pubKeyN
    String accessTokenJwt
    String wrongKeyIdAccessTokenJwt
    String wrongScopeAccessTokenJwt
    String wrongAudienceAccessTokenJwt
    String idTokenjwt
    String clientId = "OOICU812"
    String clientSecret = "VERY_SECRET"
    String authHeader = "Basic " + "${clientId}:${clientSecret}".bytes.encodeBase64().toString()

    CodeLocalValidationScenarioDefinition() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(4096)
        KeyPair keyPair = keyPairGenerator.generateKeyPair()

        pubKeyE = Base64.encodeBase64URLSafeString(TestUtils.toIntegerBytes(keyPair.publicKey.getPublicExponent()))
        pubKeyN = Base64.encodeBase64URLSafeString(TestUtils.toIntegerBytes(keyPair.publicKey.getModulus()))

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
    }

    Map getBindingMap() {
        return [
                accessTokenJwt: accessTokenJwt,
                pubKeyE: pubKeyE,
                pubKeyN: pubKeyN,
                idTokenjwt: idTokenjwt
        ]
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
                        .withQueryParam("client_id", matching(clientId))
                        .withQueryParam("redirect_uri", matching(Pattern.quote("http://localhost:")+ "\\d+/authorization-code/callback"))
                        .withQueryParam("response_type", matching("code"))
                        .withQueryParam("scope", matching("profile email openid"))
                        .withQueryParam("state", matching(".{6}"))
                        .willReturn(aResponse()
                        .withBody("<html>fake_login_page<html/>")))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withHeader("Authorization", equalTo(authHeader))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Fauthorization-code%2Fcallback") +".*"))
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBodyFile("token.json")
                        .withTransformers("gstring-template")))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withHeader("Authorization", equalTo(authHeader))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_wrongKeyIdAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Fauthorization-code%2Fcallback")  +".*"))
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBodyFile("token.json")
                        .withTransformer("gstring-template", "accessTokenJwt", wrongKeyIdAccessTokenJwt)))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withHeader("Authorization", equalTo(authHeader))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_wrongScopeAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Fauthorization-code%2Fcallback")  +".*"))
                        .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBodyFile("token.json")
                        .withTransformer("gstring-template", "accessTokenJwt", wrongScopeAccessTokenJwt)))

        wireMockServer.stubFor(
                post(urlPathEqualTo("/oauth2/default/v1/token"))
                        .withHeader("Authorization", equalTo(authHeader))
                        .withRequestBody(containing("grant_type=authorization_code"))
                        .withRequestBody(containing("code=TEST_CODE_wrongAudienceAccessTokenJwt&"))
                        .withRequestBody(matching(".*"+Pattern.quote("redirect_uri=http%3A%2F%2Flocalhost%3A") + "\\d+" +Pattern.quote("%2Fauthorization-code%2Fcallback")  +".*"))
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
}