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
package com.okta.spring.boot.oauth

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.ExchangeFunction
import org.springframework.web.reactive.function.client.WebClient
import org.testng.annotations.Test
import reactor.core.publisher.Mono

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.matchesPattern
import static org.hamcrest.Matchers.not

class WebClientUtilTest {

    @Test
    void testUserAgent() {
        HttpHeaders headers = null
        WebClient client = WebClientUtil.createWebClient().mutate()
                // mock out the response, we just want the headers
                .exchangeFunction(new ExchangeFunction() {
                    @Override
                    Mono<ClientResponse> exchange(ClientRequest request) {
                        headers = request.headers()
                        return Mono.just(ClientResponse.create(HttpStatus.OK).build())
                    }
                }).build()

        client.get()
            .accept(MediaType.APPLICATION_JSON)
            .uri("http://foo.example.com/")
            .retrieve()
            .bodyToMono(String)
            .block()

        assertThat headers.getFirst(HttpHeaders.USER_AGENT), allOf(
                    matchesPattern(".*okta-spring-security/\\d.*"),
                    matchesPattern(".* spring/\\d.*"),
                    matchesPattern(".* spring-boot/\\d.*"),
                    containsString("java/${System.getProperty("java.version")}"),
                    containsString("${System.getProperty("os.name")}/${System.getProperty("os.version")}"),
                    not(containsString('${')))
    }
}