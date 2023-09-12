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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

import java.util.Collection;

@AutoConfiguration
@AutoConfigureBefore(name = {
    "org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration",
    "org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration"})
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnOktaClientProperties
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ Flux.class, EnableWebFluxSecurity.class, ClientRegistration.class })
@Import(AuthorityProvidersConfig.class)
class ReactiveOktaOAuth2AutoConfig {

    @Value("${okta.oauth2.audience}")
    private String audience;

    @Bean
    @ConditionalOnMissingBean
    ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(Collection<AuthoritiesProvider> authoritiesProviders) {
        return new ReactiveOktaOAuth2UserService(authoritiesProviders);
    }

    @Bean
    @ConditionalOnMissingBean
    OidcReactiveOAuth2UserService oidcUserService(Collection<AuthoritiesProvider> authoritiesProviders,
                                                  @Qualifier("oauth2UserService") ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService) {
        return new ReactiveOktaOidcUserService(authoritiesProviders, oAuth2UserService);
    }

    @Bean
    @ConditionalOnBean(ReactiveJwtDecoder.class)
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ReactiveJwtDecoder jwtDecoder, ReactiveClientRegistrationRepository clientRegistrationRepository) {
        // as of Spring Security 5.4 the default chain uses oauth2Login OR a JWT resource server (NOT both)
        // this does the same as both defaults merged together (and provides the previous behavior)
        http.authorizeExchange().anyExchange().authenticated();
        Okta.configureOAuth2WithPkce(http, clientRegistrationRepository);
        http.oauth2Client();
        http.oauth2ResourceServer((server) -> customDecoder(server, jwtDecoder));
        return http.build();
    }

    private void customDecoder(ServerHttpSecurity.OAuth2ResourceServerSpec server, ReactiveJwtDecoder decoder) {
        server.jwt((jwt) -> jwt.jwtDecoder(decoder));
    }
}