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
package com.okta.spring.boot.sdk;

import com.okta.commons.configcheck.ValidationResponse;
import com.okta.commons.http.config.Proxy;
import com.okta.commons.lang.Strings;
import com.okta.sdk.authc.credentials.ClientCredentials;
import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.cache.CacheManager;
import com.okta.sdk.client.AuthorizationMode;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.client.Clients;
import com.okta.spring.boot.sdk.cache.SpringCacheManager;
import com.okta.spring.boot.sdk.config.OktaClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;

import static com.okta.commons.configcheck.ConfigurationValidator.validateApiToken;
import static com.okta.commons.configcheck.ConfigurationValidator.validateOrgUrl;

/**
 * Configure Okta's management SDK, and expose it as a Bean.
 *
 * @since 0.3.0
 */
@Configuration
@Conditional(OktaSdkConfig.OktaApiConditions.class)
@ConditionalOnClass(Client.class)
@EnableConfigurationProperties(OktaClientProperties.class)
public class OktaSdkConfig {

    private final OktaClientProperties oktaClientProperties;
    private final org.springframework.cache.CacheManager springCacheManager;

    public OktaSdkConfig(OktaClientProperties oktaClientProperties,
                         @Autowired(required = false) org.springframework.cache.CacheManager springCacheManager) {

        this.oktaClientProperties = oktaClientProperties;
        this.springCacheManager = springCacheManager;
    }

    @Bean
    protected Client oktaSdkClient() {
        ClientBuilder builder = Clients.builder()
                .setCacheManager(oktaSdkCacheManager())
                .setAuthorizationMode(AuthorizationMode.SSWS)
                .setConnectionTimeout(oktaClientProperties.getConnectionTimeout())
                .setClientCredentials(oktaSdkClientCredentials())
                .setOrgUrl(oktaClientProperties.getOrgUrl());

        Proxy proxy = oktaSdkProxy();
        if (proxy != null) {
            builder.setProxy(oktaSdkProxy());
        }

        return builder.build();
    }

    private Proxy oktaSdkProxy() {

        OktaClientProperties.ClientProxyInfo proxyInfo = oktaClientProperties.getProxy();
        if (proxyInfo == null || !Strings.hasText(proxyInfo.getHostname())) {
            return null;
        }

        Proxy proxy;

        if (Strings.hasText(proxyInfo.getUsername()) || Strings.hasText(proxyInfo.getPassword())) {
            proxy = new Proxy(proxyInfo.getHostname(), proxyInfo.getPort(), proxyInfo.getUsername(), proxyInfo.getPassword());
        } else {
            proxy = new Proxy(proxyInfo.getHostname(), proxyInfo.getPort());
        }

        return proxy;
    }

    private CacheManager oktaSdkCacheManager() {
        return (springCacheManager != null) ?
             new SpringCacheManager(springCacheManager) : null;
    }

    @Bean
    @ConditionalOnMissingBean
    protected ClientCredentials oktaSdkClientCredentials() {
        return new TokenClientCredentials(oktaClientProperties.getToken());
    }

    /**
     * Spring Boot conditional based on the existence of the properties:
     * <pre>{@code
     *  - okta.client.token
     *  - okta.client.orgUrl
     * }</pre>
     */
    static class OktaApiConditions extends SpringBootCondition {

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            ValidationResponse tokenValidation = validateApiToken(context.getEnvironment().getProperty("okta.client.token"));
            if (!tokenValidation.isValid()) {
                return ConditionOutcome.noMatch(tokenValidation.getMessage());
            }

            ValidationResponse orgUrlValidation = validateOrgUrl(context.getEnvironment().getProperty("okta.client.orgUrl"));
            if (!orgUrlValidation.isValid() &&
                !validateOrgUrl(context.getEnvironment().getProperty("okta.oauth2.issuer")).isValid()) {
                return ConditionOutcome.noMatch(orgUrlValidation.getMessage());
            }

            return ConditionOutcome.match("Okta API token and orgUrl found");
        }
    }
}