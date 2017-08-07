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
package com.okta.spring.oauth

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.provider.token.AccessTokenConverter
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier
import org.springframework.util.Assert
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.*
import static org.hamcrest.Matchers.*

@SpringBootTest(classes    = [ResourceServerConfig],
                properties = ["okta.oauth.issuer=https://okta.example.com/oauth2/my_issuer",
                              "okta.oauth.audience=custom_audience",
                              "okta.oauth.scopeClaim=custom_scope_claim",
                              "okta.oauth.rolesClaim=custom_roles_claim"])
class ResourceServerConfigTest extends AbstractTestNGSpringContextTests {

    @Autowired
    ResourceServerConfig resourceServerConfig

    @Autowired
    ResourceServerTokenServices tokenServices

    @Autowired
    TokenStore tokenStore

    @Autowired
    AccessTokenConverter accessTokenConverter

    @Autowired
    JwtClaimsSetVerifier jwtClaimsSetVerifier

    @Test
    void basicAutowireTest() {
        assertThat resourceServerConfig, notNullValue()
        assertThat tokenServices, notNullValue()
        assertThat tokenStore, notNullValue()
        assertThat accessTokenConverter, notNullValue()
        assertThat jwtClaimsSetVerifier, notNullValue()
    }

}
