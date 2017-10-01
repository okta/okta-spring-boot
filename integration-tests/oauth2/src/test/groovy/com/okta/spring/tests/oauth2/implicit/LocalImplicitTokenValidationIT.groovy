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
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.restassured.http.ContentType
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

import static com.okta.spring.tests.oauth2.TestUtils.toIntegerBytes
import static com.github.tomakehurst.wiremock.client.WireMock.*
import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.startsWith

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
                classes = [BasicImplicitFlowApplication],
                properties = ["okta.oauth2.issuer=http://localhost:9986/oauth2/default",
                              "okta.oauth2.clientId=OOICU812",
                              "server.session.trackingModes=cookie"])
class LocalImplicitTokenValidationIT extends AbstractTestNGSpringContextTests implements HttpMock {

    @LocalServerPort
    int applicationPort

    String pubKeyE
    String pubKeyN
    String accessTokenJwt
    String idTokenjwt

    RSAPrivateKey privateKey
    RSAPublicKey publicKey

    LocalImplicitTokenValidationIT() {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(4096)
        KeyPair keyPair = keyPairGenerator.generateKeyPair()
        privateKey = keyPair.private
        publicKey = keyPair.public

        pubKeyE = Base64.encodeBase64URLSafeString(toIntegerBytes(publicKey.getPublicExponent()))
        pubKeyN = Base64.encodeBase64URLSafeString(toIntegerBytes(publicKey.getModulus()))

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
                .signWith(SignatureAlgorithm.RS256, privateKey)
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
                .signWith(SignatureAlgorithm.RS256, privateKey)
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
        return 9986
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
            .header("Authorization", "Bearer ${accessTokenJwt}")
            .redirects()
                .follow(false)
        .when()
            .get("http://localhost:${applicationPort}/")
        .then()
            .body(Matchers.equalTo("The message of the day is boring: joe.coder@example.com"))
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