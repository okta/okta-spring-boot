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
