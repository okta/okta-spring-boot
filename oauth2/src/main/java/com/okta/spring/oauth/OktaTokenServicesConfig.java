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
package com.okta.spring.oauth;


import com.okta.spring.config.OktaOAuth2Properties;
import org.springframework.beans.InvalidPropertyException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.IssuerClaimVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;
import org.springframework.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;

@Configuration
@Import({OktaTokenServicesConfig.RemoteTokenValidationConfig.class,
         OktaTokenServicesConfig.LocalTokenValidationConfig.class})
public class OktaTokenServicesConfig {

    @Configuration
    @ConditionalOnProperty(prefix = "okta.oauth2",
                           name = "local-token-validation",
                           havingValue = "false")
    public static class RemoteTokenValidationConfig {

        private final OktaOAuth2Properties oktaOAuth2Properties;

        public RemoteTokenValidationConfig(OktaOAuth2Properties oktaOAuth2Properties) {
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

    @Configuration
    @ConditionalOnProperty(prefix = "okta.oauth2",
                           name = "local-token-validation",
                           matchIfMissing = true)
    public static class LocalTokenValidationConfig {

        private final OktaOAuth2Properties oktaOAuth2Properties;

        public LocalTokenValidationConfig(OktaOAuth2Properties oktaOAuth2Properties) {
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
        public TokenStore tokenStore() {
            return new JwkTokenStore(oktaOAuth2Properties.getIssuer() + "/v1/keys", accessTokenConverter(), jwtClaimsSetVerifier());
        }

        @Bean
        @ConditionalOnMissingBean
        public JwtClaimsSetVerifier jwtClaimsSetVerifier() {

            if (!StringUtils.hasText(oktaOAuth2Properties.getIssuer())) {
                throw new InvalidPropertyException(JwtClaimsSetVerifier.class, "okta.oauth2.issuer", "Property 'okta.oauth2.issuer' is required.");
            }

            try {
                return new IssuerClaimVerifier(new URL(oktaOAuth2Properties.getIssuer()));
            } catch (MalformedURLException e) {
                throw new InvalidPropertyException(JwtClaimsSetVerifier.class, "okta.oauth2.issuer", "Failed to parse issuer URL", e);
            }
        }

        @Bean
        @ConditionalOnMissingBean
        public AccessTokenConverter accessTokenConverter() {
            JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
            jwtAccessTokenConverter.setAccessTokenConverter(new ConfigurableAccessTokenConverter(oktaOAuth2Properties.getScopeClaim(), oktaOAuth2Properties.getRolesClaim()));
            return jwtAccessTokenConverter;
        }
    }
}