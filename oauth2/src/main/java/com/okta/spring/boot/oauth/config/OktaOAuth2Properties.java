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
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.Optional;
import java.util.Set;

@ConfigurationProperties("okta.oauth2")
public final class OktaOAuth2Properties implements Validator {

    private final OAuth2ClientProperties clientProperties;

    /**
     * Login route path. This property should NOT be used with applications that have multiple OAuth2 providers.
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

    public OktaOAuth2Properties(@Autowired(required = false) OAuth2ClientProperties clientProperties) {
        this.clientProperties = clientProperties;
    }

    public String getClientId() {
        return getRegistration().map(OAuth2ClientProperties.Registration::getClientId)
                                .orElse(clientId);
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return getRegistration().map(OAuth2ClientProperties.Registration::getClientSecret)
                                .orElse(clientSecret);
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

    public Set<String> getScopes() {
        return getRegistration().map(OAuth2ClientProperties.Registration::getScope)
                                .orElse(scopes);
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

    private Optional<OAuth2ClientProperties.Registration> getRegistration() {
        return Optional.ofNullable(clientProperties != null
                ? clientProperties.getRegistration().get("okta")
                : null);
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
}