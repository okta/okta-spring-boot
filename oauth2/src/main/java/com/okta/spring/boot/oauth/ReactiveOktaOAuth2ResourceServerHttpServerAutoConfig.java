/*
 * Copyright 2019-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.boot.oauth;

import com.okta.spring.boot.oauth.aot.OktaRuntimeHintsRegistrar;
import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@AutoConfiguration
@ConditionalOnOktaResourceServerProperties
@AutoConfigureAfter(ReactiveOktaOAuth2ResourceServerAutoConfig.class)
@EnableConfigurationProperties({OktaOAuth2Properties.class, OAuth2ResourceServerProperties.class})
@ConditionalOnClass({ EnableWebFluxSecurity.class, BearerTokenAuthenticationToken.class, ReactiveJwtDecoder.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ImportRuntimeHints(OktaRuntimeHintsRegistrar.class)
class ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig {

    @Bean
    static BeanPostProcessor oktaOAuth2ResourceServerBeanPostProcessor(OktaOAuth2Properties oktaOAuth2Properties,
                                                                        @Autowired(required = false) List<AuthoritiesProvider> authoritiesProviders) {
        return new OktaOAuth2ResourceServerBeanPostProcessor(oktaOAuth2Properties,
            authoritiesProviders != null ? authoritiesProviders : Collections.emptyList());
    }

    static class OktaOAuth2ResourceServerBeanPostProcessor implements BeanPostProcessor, ApplicationContextAware {

        private final OktaOAuth2Properties oktaOAuth2Properties;
        private final List<AuthoritiesProvider> authoritiesProviders;
        private ApplicationContext applicationContext;

        OktaOAuth2ResourceServerBeanPostProcessor(OktaOAuth2Properties oktaOAuth2Properties,
                                                  List<AuthoritiesProvider> authoritiesProviders) {
            this.oktaOAuth2Properties = oktaOAuth2Properties;
            this.authoritiesProviders = authoritiesProviders;
        }

        @Override
        public void setApplicationContext(ApplicationContext applicationContext) {
            this.applicationContext = applicationContext;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (bean instanceof ServerHttpSecurity) {
                final ServerHttpSecurity http = (ServerHttpSecurity) bean;
                http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(resolveJwtConverter())));
            }
            return bean;
        }

        /**
         * Resolves the JWT authentication converter to use.
         * Prefers a user-provided custom {@link JwtAuthenticationConverter} bean over
         * Okta's default, allowing full converter replacement via bean registration.
         * Note: users can also override by calling {@code jwt.jwtAuthenticationConverter(...)}
         * in their own {@code SecurityWebFilterChain} factory method, which will replace
         * whatever this BeanPostProcessor set on the {@code ServerHttpSecurity}.
         */
        private ReactiveJwtAuthenticationConverterAdapter resolveJwtConverter() {
            if (applicationContext != null) {
                Map<String, JwtAuthenticationConverter> converters =
                    applicationContext.getBeansOfType(JwtAuthenticationConverter.class);
                for (JwtAuthenticationConverter converter : converters.values()) {
                    if (!(converter instanceof OktaJwtAuthenticationConverter)) {
                        // User provided a custom JwtAuthenticationConverter bean; wrap it for reactive use
                        return new ReactiveJwtAuthenticationConverterAdapter(converter);
                    }
                }
            }
            return new ReactiveJwtAuthenticationConverterAdapter(
                new OktaJwtAuthenticationConverter(oktaOAuth2Properties, authoritiesProviders));
        }
    }
}