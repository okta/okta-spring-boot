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
package com.okta.spring.boot.oauth.config;

import com.okta.commons.configcheck.ConfigurationValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

@ConfigurationProperties("okta.oauth2")
public final class OktaOAuth2Properties implements Validator {

    // Environment replaces OAuth2ClientProperties to avoid a hard binary dependency
    // on org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties
    // which only exists in Spring Boot 4.x. In 3.x it was at
    // org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.
    // A direct constructor-param reference causes NoClassDefFoundError on SB 3.x because
    // DefaultBindConstructorProvider inspects all constructor signatures at startup.
    private final Environment environment;

    /**
     * Login route path. This property should NOT be used with applications that have multiple OAuth2 providers.
     * NOTE: this does NOT work with WebFlux, where the redirect URI will always be: /login/oauth2/code/okta
     */
    private String redirectUri;

    /**
     *  OAuth2 clientId value.
     */
    private String clientId;

    /**
     * OAuth2 client secret value.
     */
    private String clientSecret;

    /**
     * Custom authorization server issuer URL: i.e. 'https://dev-123456.oktapreview.com/oauth2/ausar5cbq5TRooicu812'.
     */
    private String issuer;

    /**
     * Authorization scopes.
     */
    private Set<String> scopes;

    /**
     * Expected access token audience claim value.
     */
    private String audience = "api://default";

    /**
     * Access token roles/groups claim key.
     */
    private String groupsClaim = "groups";

    /**
     * The token claim name to map authorities
     */
    private String authoritiesClaimName;

    /**
     * URL to redirect to after an RP-Initiated logout (SSO Logout).
     */
    private String postLogoutRedirectUri;

    /**
     * Proxy Properties
     */
    private Proxy proxy;

    // work around for https://github.com/spring-projects/spring-boot/issues/17035
    private OktaOAuth2Properties() {
        this(null);
    }

    @Autowired
    public OktaOAuth2Properties(@Autowired(required = false) Environment environment) {
        this.environment = environment;
    }

    public String getClientId() {
        if (clientId != null) { return clientId; }
        return environment != null
                ? environment.getProperty("spring.security.oauth2.client.registration.okta.client-id")
                : null;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        if (clientSecret != null) { return clientSecret; }
        return environment != null
                ? environment.getProperty("spring.security.oauth2.client.registration.okta.client-secret")
                : null;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getGroupsClaim() {
        return groupsClaim;
    }

    public void setGroupsClaim(String groupsClaim) {
        this.groupsClaim = groupsClaim;
    }

    public String getAuthoritiesClaimName() {
        return authoritiesClaimName;
    }

    public void setAuthoritiesClaimName(String authoritiesClaimName) {
        this.authoritiesClaimName = authoritiesClaimName;
    }

    public Set<String> getScopes() {
        if (scopes != null && !scopes.isEmpty()) { return scopes; }
        if (environment != null) {
            // OktaOAuth2PropertiesMappingEnvironmentPostProcessor maps okta.oauth2.scopes ->
            // spring.security.oauth2.client.registration.okta.scope, covering both
            // okta.oauth2.scopes and directly-set spring.security.oauth2.client.registration.okta.scope.
            String v = environment.getProperty("spring.security.oauth2.client.registration.okta.scope");
            if (v != null && !v.isBlank()) {
                return new LinkedHashSet<>(Arrays.asList(v.split("\s*,\s*")));
            }
        }
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }

    public Proxy getProxy() {
        return proxy;
    }

    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return OktaOAuth2Properties.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {

        OktaOAuth2Properties properties = (OktaOAuth2Properties) target;

        if (properties.getClientId() != null) {
        ConfigurationValidator.validateClientId(properties.getClientId()).ifInvalid(res ->
                errors.rejectValue("clientId", res.getMessage()));
        }

        if (properties.getClientSecret() != null) {
            ConfigurationValidator.validateClientSecret(properties.getClientSecret()).ifInvalid(res ->
                    errors.rejectValue("clientSecret", res.getMessage()));
        }

        if (properties.getIssuer() != null) {
            ConfigurationValidator.validateIssuer(properties.getIssuer()).ifInvalid(res ->
                    errors.rejectValue("issuer", res.getMessage()));
        }
    }

    public static class Proxy {

        private String host;

        private int port;

        private String username;

        private String password;

        public String getHost() {
            return host;
        }

        public void setHost(String host) {
            this.host = host;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}