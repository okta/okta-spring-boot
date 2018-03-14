/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.oauth.discovery;

import com.okta.spring.oauth.http.UserAgent;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

/**
 * OIDC discovery client.
 * NOTE: parts of this class were heavily borrowed from {code}org.springframework.security.oauth2.client.discovery.ProviderDiscoveryClient{code}
 * @since 0.2.0
 */
public class OidcDiscoveryClient {

    private final URI issuerUri;
    private final RestTemplate restTemplate = restTemplate();

    public OidcDiscoveryClient(String issuer) {

        Assert.hasText(issuer, "issuer cannot be empty");
        try {
            this.issuerUri = UriComponentsBuilder.fromHttpUrl(issuer)
                    .path("/.well-known/openid-configuration")
                    .build()
                    .encode()
                    .toUri();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid URI for issuer: " + ex.getMessage(), ex);
        }
    }

    public OidcDiscoveryMetadata discover() {
        return this.restTemplate.getForObject(issuerUri, OidcDiscoveryMetadata.class);
    }

    private static RestTemplate restTemplate() {
        RestTemplate template = new RestTemplate();
        template.getInterceptors().add(new UserAgentInterceptor());
        return template;
    }

    private static class UserAgentInterceptor implements ClientHttpRequestInterceptor {
        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            request.getHeaders().add(HttpHeaders.USER_AGENT, UserAgent.getUserAgentString());
            return execution.execute(request, body);
        }
    }
}