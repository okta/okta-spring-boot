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

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class ClaimsAuthoritiesExtractorTest {

    private Map<String, Object> dataMap = [
            number: 42,
            roles: [
                    "role1",
                    "role2"
            ],
            groups: [
                    "group1",
                    "group2"
            ],
            complex: [
                    one: 1,
                    two: "bar"
            ],
            numbers: [
                    1,
                    2,
                    3
            ],
            mixed: [
                    1,
                    null,
                    "a group",
                    "🤘"
            ]
    ]

    @Test
    void basicStringGroups() {
        def extractor = new ClaimsAuthoritiesExtractor("groups")
        assertThat extractor.extractAuthorities(dataMap), allOf(
                containsInAnyOrder(
                    new SimpleGrantedAuthority("group1"),
                    new SimpleGrantedAuthority("group2")),
                hasSize(2))
    }

    @Test
    void missingKey() {
        def extractor = new ClaimsAuthoritiesExtractor("missingKey")
        assertThat extractor.extractAuthorities(dataMap), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void complexType() {
        def extractor = new ClaimsAuthoritiesExtractor("complex")
        assertThat extractor.extractAuthorities(dataMap), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void numberType() {
        def extractor = new ClaimsAuthoritiesExtractor("numbers")
        assertThat extractor.extractAuthorities(dataMap), emptyCollectionOf(GrantedAuthority)
    }

    @Test
    void mixedTypes() {
        def extractor = new ClaimsAuthoritiesExtractor("mixed")
        assertThat extractor.extractAuthorities(dataMap), allOf(
                containsInAnyOrder(
                        new SimpleGrantedAuthority("a group"),
                        new SimpleGrantedAuthority("🤘")),
                hasSize(2))
    }

}
