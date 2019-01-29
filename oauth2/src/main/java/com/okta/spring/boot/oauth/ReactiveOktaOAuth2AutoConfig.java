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
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import reactor.core.publisher.Flux;

@Configuration
@AutoConfigureAfter(ReactiveSecurityAutoConfiguration.class)
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ Flux.class, EnableWebFluxSecurity.class, ClientRegistration.class })
@ConditionalOnBean(ReactiveSecurityAutoConfiguration.class)
class ReactiveOktaOAuth2AutoConfig {


    @Bean
    ReactiveOAuth2UserService oauth2UserService(OktaOAuth2Properties oktaOAuth2Properties) {
        return new ReactiveOktaOAuth2UserService(oktaOAuth2Properties.getGroupsClaim());
    }

    @Bean
    OidcReactiveOAuth2UserService oidcUserService(OktaOAuth2Properties oktaOAuth2Properties) {
        return new ReactiveOktaOidcUserService(oktaOAuth2Properties.getGroupsClaim());
    }
}