package com.okta.spring.boot.oauth.http

import com.fasterxml.jackson.databind.ObjectMapper
import org.mockito.ArgumentCaptor
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpResponse
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*
import static org.mockito.ArgumentMatchers.eq
import static org.mockito.Mockito.*

class Auth0ClientRequestInterceptorTest {

    @Test
    void headerAddedTest() {
        def request = mock(HttpRequest)
        def execution = mock(ClientHttpRequestExecution)
        def response = mock(ClientHttpResponse)
        def headers = mock(HttpHeaders)

        when(request.getHeaders()).thenReturn(headers)
        when(execution.execute(request, null)).thenReturn(response)

        def underTest = new Auth0ClientRequestInterceptor()
        assertThat underTest.intercept(request, null, execution), is(response)

        def auth0ClientCapture = ArgumentCaptor.forClass(String)

        verify(headers).add(eq("Auth0-Client"), auth0ClientCapture.capture())
        def auth0ClientString = auth0ClientCapture.getValue()

        def decoded = Base64.getUrlDecoder().decode(auth0ClientString)
        def auth0ClientJson = new ObjectMapper().readValue(decoded, Map)

        assertThat auth0ClientJson, allOf(
            hasEntry("name", "okta-spring-security"),
            hasEntry(equalTo("version"), is(notNullValue())),
            hasEntry(equalTo("env"), hasEntry("java", System.getProperty("java.version"))),
            hasEntry(equalTo("env"), hasEntry(equalTo("spring"), is(notNullValue()))),
            hasEntry(equalTo("env"), hasEntry(equalTo("spring-boot"), is(notNullValue()))),
            hasEntry(equalTo("env"), hasEntry(equalTo("spring-security"), is(notNullValue())))
        )
    }
}
