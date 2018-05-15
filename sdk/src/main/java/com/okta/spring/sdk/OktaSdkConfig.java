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
package com.okta.spring.sdk;

import com.okta.sdk.authc.credentials.ClientCredentials;
import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.cache.CacheManager;
import com.okta.sdk.client.AuthenticationScheme;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.client.Clients;
import com.okta.sdk.client.Proxy;
import com.okta.sdk.lang.Strings;
import com.okta.spring.config.OktaClientProperties;
import com.okta.spring.sdk.cache.SpringCacheManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * Configure Okta's management SDK, and expose it as a Bean.
 *
 * @since 0.3.0
 */
@Configuration
@Conditional(OktaSdkConfig.OktaApiTokenCondition.class)
@ConditionalOnClass(Client.class)
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
                .setAuthenticationScheme(oktaSdkAuthenticationScheme())
                .setConnectionTimeout(oktaClientProperties.getConnectionTimeout())
                .setClientCredentials(oktaSdkClientCredentials())
                .setOrgUrl(oktaClientProperties.getOrgUrl());

        Proxy proxy = oktaSdkProxy();
        if (proxy != null) {
            builder.setProxy(oktaSdkProxy());
        }

        return builder.build();
    }

    private AuthenticationScheme oktaSdkAuthenticationScheme() {
        return AuthenticationScheme.SSWS;
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
     * Spring Boot conditional based on the existance of the {code}okta.client.token{code} property.
     */
    static class OktaApiTokenCondition extends SpringBootCondition {

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {

            ConditionMessage.Builder message = ConditionMessage.forCondition("Okta Api Token Condition");
            String tokenValue = context.getEnvironment().getProperty("okta.client.token");
            if (StringUtils.hasText(tokenValue)) {
                return ConditionOutcome.match(message.foundExactly("provided API token"));
            }
            return ConditionOutcome.noMatch(message.didNotFind("provided API token").atAll());
        }
    }
}