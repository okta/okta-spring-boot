/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.spring.boot.sdk

import org.springframework.context.annotation.ConditionContext
import org.springframework.core.env.MapPropertySource
import org.springframework.mock.env.MockEnvironment
import org.testng.annotations.Test

import static com.okta.spring.boot.sdk.OktaSdkConfig.OktaApiConditions
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class OktaApiConditionsTest {

    @Test
    void testOktaApiConditionSuccess() {
        def properties = ["okta.client.token" : "my-secret-api-token",
                          "okta.client.orgUrl": "https://okta.example.com"]
        def conditionOutcome = new OktaApiConditions().getMatchOutcome(buildContext(properties), null)
        assertThat conditionOutcome.isMatch(), equalTo(true)
        assertThat conditionOutcome.getMessage(), equalTo("Okta Api Condition found provided API token and orgUrl")
    }

    @Test
    void testOktaApiConditionWithoutToken() {
        def properties = ["okta.client.orgUrl": "https://okta.example.com"]
        def conditionOutcome = new OktaApiConditions().getMatchOutcome(buildContext(properties), null)
        assertThat conditionOutcome.isMatch(), equalTo(false)
        assertThat conditionOutcome.getMessage(), equalTo("Okta Api Condition did not find provided API token")
    }

    @Test
    void testOktaApiConditionWithoutOrgUrl() {
        def properties = ["okta.client.token": "my-secret-api-token"]
        def conditionOutcome = new OktaApiConditions().getMatchOutcome(buildContext(properties), null)
        assertThat conditionOutcome.isMatch(), equalTo(false)
        assertThat conditionOutcome.getMessage(), equalTo("Okta Api Condition did not find provided API orgUrl")
    }

    private static ConditionContext buildContext(LinkedHashMap<String, String> properties) {
        def environment = new MockEnvironment()
        def context = mock(ConditionContext)
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties))
        when(context.getEnvironment()).thenReturn(environment)
        context
    }
}
