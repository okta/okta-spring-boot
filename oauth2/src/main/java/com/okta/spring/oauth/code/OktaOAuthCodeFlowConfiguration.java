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

import com.okta.spring.oauth.OAuth2AccessTokenValidationException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Spring Configuration which adds a little Okta sugar to the standard Spring Boot OAuth2 support.
 * <p>
 * Features:
 * </p>
 * <ul>
 *   <li>Customizable PrincipalExtractor based on the property {code}okta.oauth2.rolesClaim{code}</li>
 *   <li>Customizable AuthoritiesExtractor based on the property {code}okta.oauth2.principalClaim{code}</li>
 *   <li>UserInfoTokenServices that supports OAuth2 scopes from the current request</li>
 *   </ul>
 * @since 0.2.0
 */
@Configuration
class OktaOAuthCodeFlowConfiguration {

    @Configuration
    @ConditionalOnProperty(name = "okta.oauth2.localTokenValidation", matchIfMissing = true)
    public static class LocalTokenValidationConfig {
        @Bean
        @Primary
        protected ResourceServerTokenServices resourceServerTokenServices(TokenStore tokenStore,
                                                                          ResourceServerProperties resourceServerProperties) {
            DefaultTokenServices services = new AudienceValidatingTokenServices(resourceServerProperties.getServiceId());
            services.setTokenStore(tokenStore);
            return services;
        }
    }

    static class AudienceValidatingTokenServices extends DefaultTokenServices {

        private final String audience;

        AudienceValidatingTokenServices(String audience) {
            this.audience = audience;
        }

        @Override
        public OAuth2Authentication loadAuthentication(String accessTokenValue) {

            try {
                OAuth2Authentication originalOAuth = super.loadAuthentication(accessTokenValue);

                // validate audience
                if (!originalOAuth.getOAuth2Request().getResourceIds().contains(audience)) {
                    throw new OAuth2AccessTokenValidationException("Invalid token, 'aud' claim does not contain the expected audience of: " + audience);
                }

                return originalOAuth;

            } catch (InvalidSignatureException e) {
                throw new OAuth2AccessTokenValidationException("Invalid token, invalid signature", e);
            }
        }
    }
}