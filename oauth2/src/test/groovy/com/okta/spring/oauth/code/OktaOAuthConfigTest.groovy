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
package com.okta.spring.oauth.code

import com.okta.spring.oauth.discovery.DiscoveryMetadata
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails
import org.springframework.security.oauth2.common.AuthenticationScheme
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.instanceOf
import static org.hamcrest.Matchers.equalTo

@SpringBootTest(classes    = [MockCodeFlowApp, OktaOAuthConfig],
                properties = ["okta.oauth2.issuer=https://okta.example.com/oauth2/my_issuer",
                              "okta.oauth2.principalClaim=customPrincipalClaim",
                              "okta.oauth2.rolesClaim=customRoleClaim"])
class OktaOAuthConfigTest extends AbstractTestNGSpringContextTests {

    @Autowired
    @Qualifier("oktaAuthorizationCodeResourceDetails")
    AuthorizationCodeResourceDetails authorizationCodeResourceDetails

    @Autowired
    @Qualifier("oktaResourceServerProperties")
    ResourceServerProperties resourceServerProperties

    @Autowired
    DiscoveryMetadata discoveryMetadata

    @Autowired
    PrincipalExtractor principalExtractor

    @Autowired
    AuthoritiesExtractor authoritiesExtractor

    @Test
    void loadComponents() {

        assertThat authorizationCodeResourceDetails, notNullValue()
        assertThat resourceServerProperties, notNullValue()
        assertThat discoveryMetadata, notNullValue()
        assertThat principalExtractor, notNullValue()
        assertThat authoritiesExtractor, notNullValue()

        assertThat principalExtractor, instanceOf(ClaimsPrincipalExtractor)
        assertThat principalExtractor.principalClaimKey, equalTo("customPrincipalClaim")

        assertThat authoritiesExtractor, instanceOf(ClaimsAuthoritiesExtractor)
        assertThat authoritiesExtractor.rolesClaimKey, equalTo("customRoleClaim")

        assertThat resourceServerProperties.isPreferTokenInfo(), equalTo(false)
        assertThat resourceServerProperties.userInfoUri, equalTo("https://okta.example.com/userinfoEndpoint")
        assertThat resourceServerProperties.tokenInfoUri, equalTo("https://okta.example.com/introspectionEndpoint")

        assertThat authorizationCodeResourceDetails.clientAuthenticationScheme, equalTo(AuthenticationScheme.form)
        assertThat authorizationCodeResourceDetails.scope, equalTo(["openid", "profile", "email"])

    }

}
