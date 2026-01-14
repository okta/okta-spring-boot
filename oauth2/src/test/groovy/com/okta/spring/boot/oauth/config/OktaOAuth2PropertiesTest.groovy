/*
 * Copyright 2018-Present Okta, Inc.
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
package com.okta.spring.boot.oauth.config

import org.springframework.boot.security.oauth2.client.OAuth2ClientProperties
import org.springframework.validation.Errors
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.nullValue
import static org.mockito.Mockito.*

class OktaOAuth2PropertiesTest {

    @Test
    void validationErrors_allInvalidTest() {

        def oauthProps = mock(OAuth2ClientProperties)
        def oktaRegistration = mock(OAuth2ClientProperties.Registration)
        def regMap = [okta: oktaRegistration]
        def errors = mock(Errors)

        when(oauthProps.getRegistration()).thenReturn(regMap)
        when(oktaRegistration.getClientId()).thenReturn("{clientId}")
        when(oktaRegistration.getClientSecret()).thenReturn("{clientSecret}")

        def underTest = new OktaOAuth2Properties(oauthProps)
        underTest.setIssuer("foobar")
        underTest.validate(underTest, errors)

        verify(errors).rejectValue(eq("issuer"), startsWith("It looks like there's a typo in your Okta Issuer URL"))
        verify(errors).rejectValue(eq("issuer"), contains("foobar"))
        verify(errors).rejectValue(eq("clientId"), contains("Replace {clientId}"))
        verify(errors).rejectValue(eq("clientSecret"), contains("Replace {clientSecret}"))
    }

    @Test
    void validationErrors_issuerNonHttpsTest() {

        def oauthProps = mock(OAuth2ClientProperties)
        def oktaRegistration = mock(OAuth2ClientProperties.Registration)
        def regMap = [okta: oktaRegistration]
        def errors = mock(Errors)

        when(oauthProps.getRegistration()).thenReturn(regMap)

        def underTest = new OktaOAuth2Properties(oauthProps)
        underTest.setIssuer("http://okta.example.com")
        underTest.validate(underTest, errors)

        verify(errors).rejectValue(eq("issuer"), contains("Your Okta Issuer URL must start with https"))
        verify(errors).rejectValue(eq("issuer"), contains("http://okta.example.com"))
    }

    @Test
    void accessNullClientIdWithoutSpringOAuthProps() {

        def oauthProps = mock(OAuth2ClientProperties)
        def regMap = [okta: null]

        when(oauthProps.getRegistration()).thenReturn(regMap)

        def underTest = new OktaOAuth2Properties(oauthProps)
        assertThat underTest.clientId, nullValue()
    }

    @Test
    void accessValidClientIdWithoutSpringOAuthProps() {
        def oauthProps = mock(OAuth2ClientProperties)
        def regMap = [okta: null]
        when(oauthProps.getRegistration()).thenReturn(regMap)

        def underTest = new OktaOAuth2Properties(oauthProps)
        underTest.setClientId("a-client-id")
        assertThat underTest.clientId, is("a-client-id")
    }
}