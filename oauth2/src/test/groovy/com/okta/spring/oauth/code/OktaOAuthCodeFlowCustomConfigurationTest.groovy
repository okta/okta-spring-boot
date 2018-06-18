/*
 * Copyright 2018-present Okta, Inc.
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

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2SsoCustomConfiguration
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.isA
import static org.hamcrest.Matchers.notNullValue

/**
 * Ensures a Spring Security {@link OAuth2SsoCustomConfiguration} when OktaOAuthCodeFlowCustomConfiguration is used and
 * a {@link org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter WebSecurityConfigurerAdapter} is found with a @{@link org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso EnableOAuth2Sso}.
 *
 * @since 0.6.0
 */
class OktaOAuthCodeFlowCustomConfigurationTest extends AbstractTestNGSpringContextTests {

    @SpringBootTest(classes    = [MockCustomSsoCodeFlowApp, OktaOAuthCodeFlowCustomConfiguration],
                    properties = ["okta.oauth2.issuer=https://okta.example.com/oauth2/my_issuer",
                                  "okta.oauth2.discoveryDisabled=true",
                                  "okta.oauth2.localTokenValidation=false"])
    static class RemoteValidationConfigTest extends AbstractTestNGSpringContextTests {

        @Autowired
        OAuth2SsoCustomConfiguration oAuth2SsoCustomConfiguration

        @Autowired
        AuthoritiesExtractor authoritiesExtractor

        @Test
        void theBasics() {
            assertThat authoritiesExtractor, notNullValue()
            assertThat oAuth2SsoCustomConfiguration, notNullValue()
        }
    }

    @SpringBootTest(classes    = [MockCustomSsoCodeFlowApp, OktaOAuthCodeFlowCustomConfiguration],
                    properties = ["okta.oauth2.issuer=https://okta.example.com/oauth2/my_issuer",
                                  "okta.oauth2.discoveryDisabled=true"])
    static class LocalValidationConfigTest extends AbstractTestNGSpringContextTests {

        @Autowired
        OAuth2SsoCustomConfiguration oAuth2SsoCustomConfiguration

        @Autowired
        TokenStore tokenStore

        @Test
        void theBasics() {
            assertThat tokenStore, isA(JwkTokenStore)
            assertThat oAuth2SsoCustomConfiguration, notNullValue()
        }
    }
}