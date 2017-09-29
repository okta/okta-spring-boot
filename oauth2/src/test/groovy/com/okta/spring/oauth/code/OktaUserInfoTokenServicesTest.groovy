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

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.client.OAuth2ClientContext
import org.springframework.security.oauth2.client.OAuth2RestOperations
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

/**
 * @since 0.2.0
 */
class OktaUserInfoTokenServicesTest {

    @Test
    void retrieveScopeTest() {

        // mocks
        def responseMapBody = [foo: "bar"] // must be non empty
        def tokenString = "mock-access-token"
        def userInfoEndpoint = "https://example.com/token"
        def oauthToken = mock(OAuth2AccessToken)
        def oauthContext = mock(OAuth2ClientContext)
        def oauthRestTemplate = mock(OAuth2RestOperations)
        when(oauthRestTemplate.getOAuth2ClientContext()).thenReturn(oauthContext)
        when(oauthContext.getAccessToken()).thenReturn(oauthToken)
        when(oauthToken.getValue()).thenReturn(tokenString)
        when(oauthToken.getScope()).thenReturn(["one", "two", "red", "blue"].toSet())
        when(oauthRestTemplate.getForEntity(userInfoEndpoint, Map)).thenReturn(new ResponseEntity<Map>(responseMapBody, HttpStatus.OK))

        // configure the service
        def tokenServices = new OktaUserInfoTokenServices(userInfoEndpoint, "client-id", oauthContext)
        tokenServices.restTemplate = oauthRestTemplate

        // try to get the auth
        OAuth2Authentication auth = tokenServices.loadAuthentication(tokenString)
        assertThat auth.getOAuth2Request().scope, equalTo(["one", "two", "red", "blue"].toSet())

    }
}
