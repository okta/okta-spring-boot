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
package com.okta.spring.boot.sdk

import com.okta.sdk.client.Client
import com.okta.spring.boot.sdk.cache.SpringCacheManager
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

@SpringBootTest(classes    = [MockSdkAppWithCache],
                properties = ["okta.client.orgUrl=https://okta.example.com",
                              "okta.client.token=my-secret-api-token",
                              "okta.oauth2.discoveryDisabled=true"])
class OktaSdkConfigWithCacheTest extends AbstractTestNGSpringContextTests {

    @Autowired
    Client client

    @Test
    void correctCacheImpl() {
        assertThat client.dataStore.cacheManager, instanceOf(SpringCacheManager)
    }
}