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

import com.okta.spring.oauth.ClaimsPrincipalExtractor
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.nullValue

/**
 * @since 0.2.0
 */
class ClaimsPrincipalExtractorTest {

    private Map<String, Object> dataMap = [
        expectedKey: "joe.coder@example.com",
        expectedKey1: "jill.code@example.com",
        number: 42,
        subMap: [
            key1: "value1",
            key2: "value2"
        ]
    ]

    @Test
    void stringPrincipal() {
        def extractor = new ClaimsPrincipalExtractor("expectedKey")
        assertThat extractor.extractPrincipal(dataMap), equalTo("joe.coder@example.com")
    }

    @Test
    void numberPrincipal() {
        def extractor = new ClaimsPrincipalExtractor("number")
        assertThat extractor.extractPrincipal(dataMap), equalTo(42)
    }

    @Test
    void mapPrincipal() {
        def extractor = new ClaimsPrincipalExtractor("subMap")
        assertThat extractor.extractPrincipal(dataMap), equalTo([
                key1: "value1",
                key2: "value2"
        ])
    }

    @Test
    void missingValue() {
        def extractor = new ClaimsPrincipalExtractor("missingKey")
        assertThat extractor.extractPrincipal(dataMap), nullValue()

    }
}
