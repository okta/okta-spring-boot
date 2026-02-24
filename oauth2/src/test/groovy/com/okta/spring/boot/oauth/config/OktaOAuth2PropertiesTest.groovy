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

import org.springframework.core.env.Environment
import org.springframework.validation.Errors
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.nullValue
import static org.mockito.Mockito.*

class OktaOAuth2PropertiesTest {

    @Test
    void validationErrors_allInvalidTest() {

        def env = mock(Environment)
        def errors = mock(Errors)

        // Simulate Spring properties carrying placeholder values
        when(env.getProperty("spring.security.oauth2.client.registration.okta.client-id")).thenReturn("{clientId}")
        when(env.getProperty("spring.security.oauth2.client.registration.okta.client-secret")).thenReturn("{clientSecret}")

        def underTest = new OktaOAuth2Properties(env)
        underTest.setIssuer("foobar")
        underTest.validate(underTest, errors)

        verify(errors).rejectValue(eq("issuer"), startsWith("It looks like there's a typo in your Okta Issuer URL"))
        verify(errors).rejectValue(eq("issuer"), contains("foobar"))
        verify(errors).rejectValue(eq("clientId"), contains("Replace {clientId}"))
        verify(errors).rejectValue(eq("clientSecret"), contains("Replace {clientSecret}"))
    }

    @Test
    void validationErrors_issuerNonHttpsTest() {

        def env = mock(Environment)
        def errors = mock(Errors)

        def underTest = new OktaOAuth2Properties(env)
        underTest.setIssuer("http://okta.example.com")
        underTest.validate(underTest, errors)

        verify(errors).rejectValue(eq("issuer"), contains("Your Okta Issuer URL must start with https"))
        verify(errors).rejectValue(eq("issuer"), contains("http://okta.example.com"))
    }

    @Test
    void accessNullClientIdWithoutSpringOAuthProps() {

        def env = mock(Environment)
        when(env.getProperty("spring.security.oauth2.client.registration.okta.client-id")).thenReturn(null)

        def underTest = new OktaOAuth2Properties(env)
        assertThat underTest.clientId, nullValue()
    }

    @Test
    void accessValidClientIdWithoutSpringOAuthProps() {

        def env = mock(Environment)

        def underTest = new OktaOAuth2Properties(env)
        underTest.setClientId("a-client-id")
        assertThat underTest.clientId, is("a-client-id")
    }
}
