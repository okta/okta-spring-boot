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
package com.okta.spring.oauth.code;

import com.okta.spring.config.OktaOAuth2Properties;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2SsoDefaultConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

@Configuration
@AutoConfigureBefore(OAuth2SsoDefaultConfiguration.class)
@ConditionalOnBean(OAuth2SsoDefaultConfiguration.class)
public class OktaOAuthCodeFlowConfiguration {

    private final OktaOAuth2Properties oktaOAuth2Properties;

    public OktaOAuthCodeFlowConfiguration(OktaOAuth2Properties oktaOAuth2Properties) {
        this.oktaOAuth2Properties = oktaOAuth2Properties;
    }

    @Bean
    @ConditionalOnMissingBean
    protected AuthoritiesExtractor authoritiesExtractor() {
        return new ClaimsAuthoritiesExtractor(oktaOAuth2Properties.getRolesClaim());
    }

    @Bean
    @ConditionalOnMissingBean
    protected PrincipalExtractor principalExtractor() {
        return new ClaimsPrincipalExtractor(oktaOAuth2Properties.getPrincipalClaim());
    }

    @Bean
    @Primary
    protected ResourceServerTokenServices resourceServerTokenServices(ResourceServerProperties sso,
                                                                      OAuth2ClientContext oauth2ClientContext,
                                                                      UserInfoRestTemplateFactory restTemplateFactory) {

        UserInfoTokenServices services = new OktaUserInfoTokenServices(sso.getUserInfoUri(), sso.getClientId(), oauth2ClientContext);
        services.setRestTemplate(restTemplateFactory.getUserInfoRestTemplate());
        services.setTokenType(sso.getTokenType());
        services.setAuthoritiesExtractor(authoritiesExtractor());
        services.setPrincipalExtractor(principalExtractor());
        return services;
    }
}