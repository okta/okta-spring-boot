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

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.net.URI;
import java.util.Collection;

@Configuration
@ConditionalOnOktaClientProperties
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnClass({ EnableWebSecurity.class, ClientRegistration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Import(AuthorityProvidersConfig.class)
class OktaOAuth2AutoConfig {

    @Bean
    @ConditionalOnProperty(name = "okta.oauth2.post-logout-redirect-uri")
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(OktaOAuth2Properties oktaOAuth2Properties,
                                                                     ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri(URI.create(oktaOAuth2Properties.getPostLogoutRedirectUri()));
        return successHandler;
    }

    @Bean
    @ConditionalOnMissingBean(name="oAuth2UserService")
    OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService(Collection<AuthoritiesProvider> authoritiesProviders) {
        return new OktaOAuth2UserService(authoritiesProviders);
    }

    @Bean
    @ConditionalOnMissingBean(name="oidcUserService")
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(Collection<AuthoritiesProvider> authoritiesProviders) {
        return new OktaOidcUserService(oAuth2UserService(authoritiesProviders), authoritiesProviders);
    }
}