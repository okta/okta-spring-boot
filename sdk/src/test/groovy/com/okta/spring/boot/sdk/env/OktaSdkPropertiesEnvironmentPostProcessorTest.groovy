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
package com.okta.spring.boot.sdk.env


import org.springframework.core.env.MapPropertySource
import org.springframework.mock.env.MockEnvironment
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class OktaSdkPropertiesEnvironmentPostProcessorTest {

    @Test
    void testResolveEmptyOrgUrl() {
        def environment = new MockEnvironment()
        def properties = ["okta.oauth2.issuer": "https://okta.example.com/oauth2/default"]
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties))

        new OktaSdkPropertiesEnvironmentPostProcessor().resolveEmptyOrgUrl(environment)

        assertThat environment.getProperty("okta.client.orgUrl"), is("https://okta.example.com/")
    }
}
