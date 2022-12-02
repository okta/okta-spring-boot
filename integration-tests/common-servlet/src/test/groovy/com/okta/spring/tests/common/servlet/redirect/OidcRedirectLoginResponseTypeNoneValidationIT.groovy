/*
 * Copyright 2022 Okta, Inc.
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
package com.okta.spring.tests.common.servlet.redirect

import com.okta.test.mock.Scenario
import com.okta.test.mock.tests.BaseValidationIT
import io.restassured.http.ContentType
import org.hamcrest.Matcher
import org.testng.annotations.Test

import static com.okta.test.mock.matchers.UrlMatcher.singleQueryValue
import static com.okta.test.mock.matchers.UrlMatcher.urlMatcher
import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.text.MatchesPattern.matchesPattern

@Scenario(com.okta.test.mock.scenarios.Scenario.OIDC_FLOW_NONE_RESPONSE_TYPE_VALIDATION)
class OidcRedirectLoginResponseTypeNoneValidationIT extends BaseValidationIT {

    @Test
    void followRedirectWithPkce() {
        given()
            .redirects()
                .follow(false)
            .accept(ContentType.JSON)
        .when()
            .get("http://localhost:${applicationPort}${protectedPath}")
        .then()
            .statusCode(302)
            .header("Location", loginPageLocationMatcher())
            .log().everything()
    }

    @Override
    Matcher loginPageLocationMatcher() {
        return allOf(
            urlMatcher("${baseUrl}/oauth2/default/v1/authorize",
                singleQueryValue("response_type", "none"),
                singleQueryValue("code_challenge_method", "S256"),
                singleQueryValue("acr_values", "urn:okta:loa:2fa:any:ifpossible"),
                singleQueryValue("prompt", "enroll_authenticator"),
                singleQueryValue("max_age", "0"),
                singleQueryValue("code_challenge", matchesPattern(".{43}"))))
    }
}
