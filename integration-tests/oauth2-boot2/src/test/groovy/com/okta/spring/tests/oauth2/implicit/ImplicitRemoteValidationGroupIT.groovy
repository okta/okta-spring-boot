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

import com.github.tomakehurst.wiremock.http.RequestMethod
import com.okta.test.mock.Scenario
import com.okta.test.mock.application.ApplicationTestRunner
import org.hamcrest.Matchers
import org.testng.annotations.Test

import static com.github.tomakehurst.wiremock.client.WireMock.containing
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching
import static com.github.tomakehurst.wiremock.matching.RequestPatternBuilder.newRequestPattern
import static io.restassured.RestAssured.given
import static com.okta.test.mock.scenarios.Scenario.IMPLICIT_FLOW_REMOTE_VALIDATION

@Scenario(IMPLICIT_FLOW_REMOTE_VALIDATION)
class ImplicitRemoteValidationGroupIT extends ApplicationTestRunner {

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

        wireMockServer.verify(
                newRequestPattern(RequestMethod.GET, urlMatching("/oauth2/default/v1/userinfo")))
    }

    @Test
    void validateUserAgent() {

        ResourceBundle versions = ResourceBundle.getBundle("versions")
        def springIntegrationVersion = versions.getString("project.version")

        // discovery
        wireMockServer.verify(
                newRequestPattern(RequestMethod.GET, urlMatching("/oauth2/default/.well-known/openid-configuration"))
                    .withHeader("User-Agent", containing("okta-spring-security/${springIntegrationVersion}"))
        )
    }
}