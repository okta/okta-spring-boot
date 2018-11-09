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
package com.okta.spring.boot.oauth.http

import org.hamcrest.MatcherAssert
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpResponse
import org.testng.annotations.Test

import static org.hamcrest.Matchers.is
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.verify
import static org.mockito.Mockito.when
import static org.hamcrest.MatcherAssert.assertThat

class UserAgentRequestInterceptorTest {

    @Test
    void headerAddedTest() {

        def request = mock(HttpRequest)
        def execution = mock(ClientHttpRequestExecution)
        def response = mock(ClientHttpResponse)
        def headers = mock(HttpHeaders)

        when(request.getHeaders()).thenReturn(headers)
        when(execution.execute(request, null)).thenReturn(response)

        def underTest = new UserAgentRequestInterceptor()
        assertThat underTest.intercept(request, null, execution), is(response)

        verify(headers).add("User-Agent", UserAgent.userAgentString)
    }
}
