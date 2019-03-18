/*
 * Copyright 2002-2018 the original author or authors.
 * Modifications Copyright 2019 Okta, Inc.
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

package com.okta.spring.boot.oauth;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static com.okta.spring.boot.oauth.Okta.statusAsString;

/**
 * An {@link AuthenticationEntryPoint} implementation used to commence authentication of protected resource requests
 * using {@link BearerTokenAuthenticationFilter}.
 * <p>
 * Uses information provided by {@link BearerTokenError} to set HTTP response status code and populate
 * {@code WWW-Authenticate} HTTP header.
 *
 * @author Rob Winch
 * @since 1.2.0
 * @see BearerTokenError
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 * Response Header Field</a>
 */
final class BrowserFriendlyBearerTokenServerAuthenticationEntryPoint implements
        ServerAuthenticationEntryPoint {

    private String realmName;

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException authException) {
        return Mono.defer(() -> {
            HttpStatus status = getStatus(authException);

            Map<String, String> parameters = createParameters(authException);
            String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
            ServerHttpResponse response = exchange.getResponse();
            response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
            response.setStatusCode(status);

            response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            DataBuffer buffer = response.bufferFactory().wrap(statusAsString(status).getBytes(StandardCharsets.UTF_8));
            return response.writeWith(Mono.just(buffer));
        });
    }

    private Map<String, String> createParameters(AuthenticationException authException) {
        Map<String, String> parameters = new LinkedHashMap<>();
        if (this.realmName != null) {
            parameters.put("realm", this.realmName);
        }

        if (authException instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();

            parameters.put("error", error.getErrorCode());

            if (StringUtils.hasText(error.getDescription())) {
                parameters.put("error_description", error.getDescription());
            }

            if (StringUtils.hasText(error.getUri())) {
                parameters.put("error_uri", error.getUri());
            }

            if (error instanceof BearerTokenError) {
                BearerTokenError bearerTokenError = (BearerTokenError) error;

                if (StringUtils.hasText(bearerTokenError.getScope())) {
                    parameters.put("scope", bearerTokenError.getScope());
                }
            }
        }
        return parameters;
    }

    private HttpStatus getStatus(AuthenticationException authException) {
        return Okta.getStatus(authException);
    }

    private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
        String wwwAuthenticate = "Bearer";
        if (!parameters.isEmpty()) {
            wwwAuthenticate += parameters.entrySet().stream()
                    .map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
                    .collect(Collectors.joining(", ", " ", ""));
        }

        return wwwAuthenticate;
    }
}
