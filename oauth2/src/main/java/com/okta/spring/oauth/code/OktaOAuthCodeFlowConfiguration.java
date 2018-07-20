/*
 * Copyright 2017-Present Okta, Inc.
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
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
        protected ResourceServerTokenServices resourceServerTokenServices(TokenStore tokenStore, OktaOAuth2Properties properties) {
            DefaultTokenServices services = new CodeFlowAudienceValidatingTokenServices(properties.getAudience());
            services.setTokenStore(tokenStore);
            return services;
        }
    }
}