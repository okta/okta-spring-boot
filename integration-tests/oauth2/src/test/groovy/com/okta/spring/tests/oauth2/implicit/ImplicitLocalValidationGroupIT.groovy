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
import com.okta.test.mock.tests.TestUtils
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.apache.commons.codec.binary.Base64
import org.hamcrest.Matchers
import org.testng.annotations.Test

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Instant
import java.time.temporal.ChronoUnit

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse
import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import static io.restassured.RestAssured.given

@Scenario("implicit-flow-local-validation")
class ImplicitLocalValidationGroupIT extends ApplicationTestRunner {

    String pubKeyE
    String pubKeyN
    String accessTokenJwt

    ImplicitLocalValidationGroupIT() {

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
                .claim("groups", ["Everyone", "Test-Group"])
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                .setKeyId('TEST_PUB_KEY_ID'))
                .signWith(SignatureAlgorithm.RS256, keyPair.privateKey)
                .compact()
    }

    @Override
    Map getBindingMap() {
        return [
                accessTokenJwt: accessTokenJwt,
                baseUrl: getBaseUrl(),
                pubKeyE: pubKeyE,
                pubKeyN: pubKeyN
        ]
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
    }

    @Test
    void groupAccessTest() {
        given()
            .header("Authorization", "Bearer ${accessTokenJwt}")
            .redirects()
                .follow(false)
        .when()
            .get("http://localhost:${applicationPort}/everyone")
        .then()
            .body(Matchers.equalTo("Everyone has Access: joe.coder@example.com"))
    }
}
