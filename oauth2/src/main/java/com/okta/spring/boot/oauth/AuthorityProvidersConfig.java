/*
 * Copyright 2019-Present Okta, Inc.
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

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @since 1.4.0
 */
@Configuration
class AuthorityProvidersConfig {

    @Bean
    AuthoritiesProvider tokenScopesAuthoritiesProvider() {
        return (user, userRequest) -> TokenUtil.tokenScopesToAuthorities(userRequest.getAccessToken());
    }

    @Bean
    AuthoritiesProvider groupClaimsAuthoritiesProvider(OktaOAuth2Properties oktaOAuth2Properties) {
        return (user, userRequest) -> TokenUtil.tokenClaimsToAuthorities(user.getAttributes(), oktaOAuth2Properties.getGroupsClaim());
    }
}