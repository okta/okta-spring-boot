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
import com.okta.spring.boot.oauth.http.UserAgentRequestInterceptor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Flux;

import java.util.Arrays;
import java.util.Collection;

@Configuration
@AutoConfigureAfter(ReactiveSecurityAutoConfiguration.class)
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnOktaClientProperties
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ Flux.class, EnableWebFluxSecurity.class, ClientRegistration.class })
@ConditionalOnBean(ReactiveSecurityAutoConfiguration.class)
@Import(AuthorityProvidersConfig.class)
class ReactiveOktaOAuth2AutoConfig {

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
    OpaqueTokenIntrospector opaqueTokenIntrospector(OktaOAuth2Properties oktaOAuth2Properties,
                                                    OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {
        return new NimbusOpaqueTokenIntrospector(
            oAuth2ResourceServerProperties.getOpaquetoken().getIntrospectionUri(),
            oktaOAuth2Properties.getClientId(),
            oktaOAuth2Properties.getClientSecret());
    }

    @Bean
    RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
            new FormHttpMessageConverter(),
            new OAuth2AccessTokenResponseHttpMessageConverter(),
            new StringHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());
        return restTemplate;
    }
}