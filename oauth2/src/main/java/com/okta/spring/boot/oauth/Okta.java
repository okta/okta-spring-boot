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
package com.okta.spring.boot.oauth;

import com.okta.commons.lang.Strings;
import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;

import java.util.Map;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers.withPkce;

/**
 * Okta + Spring Security utility methods.
 * @since 1.2.0
 */
public final class Okta {

    private Okta() {}

    /**
     * Configures the {@code http} to return a NON-EMPTY response body if the client supports the Media Type text/plain.
     * This is to work around an issue with Chrome, when a response body is empty, Chrome will show a `This site can’t be reached`, ERR_INVALID_RESPONSE error.
     * The body content will contain the HTTP Status and simple message such as `401 Unauthorized`.
     *
     * @param http the ServerHttpSecurity to configure
     * @return the {@code http} to allow method chaining
     */
    public static ServerHttpSecurity configureResourceServer401ResponseBody(ServerHttpSecurity http) {
        return http.exceptionHandling()
                .authenticationEntryPoint(new DelegatingServerAuthenticationEntryPoint(
                                                // clients that accept plain text, browsers, curl, etc
                                                new DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                                                        new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_PLAIN),
                                                        new BrowserFriendlyBearerTokenServerAuthenticationEntryPoint()),

                                                // any non text client application/json etc
                                                new DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                                                        new MediaTypeServerWebExchangeMatcher(MediaType.ALL),
                                                        new BearerTokenServerAuthenticationEntryPoint()))).and();
    }

    /**
     * Configures the {@code http} to return a NON-EMPTY response body if the client supports the Media Type text/plain.
     * This is to work around an issue with Chrome, when a response body is empty, Chrome will show a `This site can’t be reached`, ERR_INVALID_RESPONSE error.
     * The body content will contain the HTTP Status and simple message such as `401 Unauthorized`.
     *
     * @param http the HttpSecurity to configure
     * @return the {@code http} to allow method chaining
     */
    public static HttpSecurity configureResourceServer401ResponseBody(HttpSecurity http) throws Exception {
        return http.exceptionHandling()
                    .defaultAuthenticationEntryPointFor(authenticationEntryPoint(), textRequestMatcher(http)).and();
    }

    /**
     * Configures the {@code http} with an OAuth2 Login, that supports PKCE. The default Spring Security implementation
     * only enables PKCE for public clients.
     * <p>
     * <b>NOTE:</b> Enabling PKCE will be required for all clients (public and confidential) in the future OAuth 2.1 spec.
     *
     * @param http the ServerHttpSecurity to configure
     * @param clientRegistrationRepository the repository bean, this should be injected into the calling method.
     * @return the {@code http} to allow method chaining
     */
    public static ServerHttpSecurity configureOAuth2WithPkce(ServerHttpSecurity http, ReactiveClientRegistrationRepository clientRegistrationRepository) {
        // Create a request resolver that enables PKCE
        DefaultServerOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        authorizationRequestResolver.setAuthorizationRequestCustomizer(withPkce());
        // enable oauth2 login that uses PKCE
        http.oauth2Login().authorizationRequestResolver(authorizationRequestResolver);

        return http;
    }

    /**
     * Configures the {@code http} with an OAuth2 Login that supports PKCE and additional Okta supported authorization request query params.
     * The default Spring Security implementation only enables PKCE for public clients.
     * <p>
     * <b>NOTE:</b> Enabling PKCE will be required for all clients (public and confidential) in the future OAuth 2.1 spec.
     *
     * @param http the HttpSecurity to configure
     * @param clientRegistrationRepository the repository bean, this should be injected into the calling method.
     * @return the {@code http} to allow method chaining
     * @throws Exception the exception
     */
    public static HttpSecurity configureOAuth2WithPkceAndAuthReqParams(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        OktaOAuth2Properties oktaOAuth2Properties = context.getBean(OktaOAuth2Properties.class);

        // Create a request resolver that enables PKCE
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(withPkce().andThen(builder -> {
            builder.additionalParameters(params -> addCustomAuthorizationRequestParams(params, oktaOAuth2Properties));
        }));

        // enable oauth2 login that uses PKCE
        http.oauth2Login()
            .authorizationEndpoint()
            .authorizationRequestResolver(authorizationRequestResolver);

        return http;
    }

    private static void addCustomAuthorizationRequestParams(Map<String, Object> params, OktaOAuth2Properties oktaOAuth2Properties) {

        if (Strings.hasText(oktaOAuth2Properties.getAcrValues())) {
            params.put(OktaOAuth2CustomParam.ACR_VALUES, oktaOAuth2Properties.getAcrValues());
        }
        if (Strings.hasText(oktaOAuth2Properties.getPrompt())) {
            params.put(OktaOAuth2CustomParam.PROMPT, oktaOAuth2Properties.getPrompt());

            // Okta enforced rules
            if (oktaOAuth2Properties.getPrompt().equals("enroll_authenticator")) {
                params.put(OAuth2ParameterNames.RESPONSE_TYPE, "none");
                params.put(OktaOAuth2CustomParam.ACR_VALUES, "urn:okta:loa:2fa:any:ifpossible");
                params.put(OktaOAuth2CustomParam.MAX_AGE, "0");
                params.remove(OAuth2ParameterNames.SCOPE);

                String enrollmentCallbackUri = oktaOAuth2Properties.getEnrollmentCallbackUri();
                if (Strings.hasText(enrollmentCallbackUri)) {
                    params.put(OAuth2ParameterNames.REDIRECT_URI, enrollmentCallbackUri);
                }
            }
        }
        if (Strings.hasText(oktaOAuth2Properties.getEnrollAmrValues())) {
            params.put(OktaOAuth2CustomParam.ENROLL_AMR_VALUES, oktaOAuth2Properties.getEnrollAmrValues());
        }
    }

    private static RequestMatcher textRequestMatcher(HttpSecurity http) {
        return new MediaTypeRequestMatcher(http.getSharedObject(ContentNegotiationStrategy.class), MediaType.TEXT_PLAIN);
    }

    private static AuthenticationEntryPoint authenticationEntryPoint() {
        BearerTokenAuthenticationEntryPoint bearerTokenEntryPoint = new BearerTokenAuthenticationEntryPoint();
        return (request, response, authException) -> {
            response.setContentType(MediaType.TEXT_PLAIN.toString());
            response.getWriter().print(statusAsString(Okta.getStatus(authException)));
            bearerTokenEntryPoint.commence(request, response, authException);
        };
    }

    static HttpStatus getStatus(AuthenticationException authException) {
        if (authException instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();
            if (error instanceof BearerTokenError) {
                return ((BearerTokenError) error).getHttpStatus();
            }
        }
        return HttpStatus.UNAUTHORIZED;
    }

    static String statusAsString(HttpStatus status) {
        return status.value() + " " + status.getReasonPhrase();
    }

}