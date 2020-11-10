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

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;

import java.lang.reflect.Field;
import java.net.MalformedURLException;

@Configuration
@ConditionalOnOktaResourceServerProperties
@AutoConfigureAfter(ReactiveOktaOAuth2ResourceServerAutoConfig.class)
@EnableConfigurationProperties({OktaOAuth2Properties.class, OAuth2ResourceServerProperties.class})
@ConditionalOnClass({ EnableWebFluxSecurity.class, BearerTokenAuthenticationToken.class, ReactiveJwtDecoder.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
class ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig {

    private static final Logger log = LoggerFactory.getLogger(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig.class);

    @Bean
    BeanPostProcessor oktaOAuth2ResourceServerBeanPostProcessor(OktaOAuth2Properties oktaOAuth2Properties) {
        return new OktaOAuth2ResourceServerBeanPostProcessor(oktaOAuth2Properties);
    }

    static class OktaOAuth2ResourceServerBeanPostProcessor implements BeanPostProcessor {

        private final OktaOAuth2Properties oktaOAuth2Properties;

        OktaOAuth2ResourceServerBeanPostProcessor(OktaOAuth2Properties oktaOAuth2Properties) {
            this.oktaOAuth2Properties = oktaOAuth2Properties;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (bean instanceof ServerHttpSecurity) {
                final ServerHttpSecurity http = (ServerHttpSecurity) bean;
                ServerHttpSecurity.OAuth2ResourceServerSpec oAuth2ResourceServerSpec = http.oauth2ResourceServer();

                try {
                    if (TokenUtil.isRootOrgIssuer(oktaOAuth2Properties.getIssuer())) {
                        log.debug("Opaque Token validation/introspection will be configured.");
                        http.oauth2ResourceServer().opaqueToken();
                        return http;
                    }
                } catch (MalformedURLException ex) {
                    throw new IllegalArgumentException(ex.getMessage());
                }

                try {
                    Field jwtPrivateStringField = ServerHttpSecurity.OAuth2ResourceServerSpec.class.
                        getDeclaredField("jwt");
                    Field opaqueTokenPrivateStringField = ServerHttpSecurity.OAuth2ResourceServerSpec.class.
                        getDeclaredField("opaqueToken");

                    jwtPrivateStringField.setAccessible(true);
                    opaqueTokenPrivateStringField.setAccessible(true);

                    ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec jwtSpecValue =
                        (ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec) jwtPrivateStringField.get(oAuth2ResourceServerSpec);
                    ServerHttpSecurity.OAuth2ResourceServerSpec.OpaqueTokenSpec opaqueTokenSpecValue =
                        (ServerHttpSecurity.OAuth2ResourceServerSpec.OpaqueTokenSpec) opaqueTokenPrivateStringField.get(oAuth2ResourceServerSpec);

                    if (jwtSpecValue != null) {
                        log.debug("JWT Token validation/introspection will be configured.");
                        http.oauth2ResourceServer().jwt()
                            .jwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(
                                new OktaJwtAuthenticationConverter(oktaOAuth2Properties.getGroupsClaim())));
                    } else if (opaqueTokenSpecValue != null) {
                        log.debug("Opaque Token validation/introspection will be configured.");
                        http.oauth2ResourceServer().opaqueToken();
                    } else {
                        log.debug("Defaulting to JWT Token validation/introspection configuration.");
                        http.oauth2ResourceServer().jwt()
                            .jwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(
                                new OktaJwtAuthenticationConverter(oktaOAuth2Properties.getGroupsClaim())));
                    }
                } catch (NoSuchFieldException | IllegalAccessException e) {
                    log.error("Error occurred", e);
                    //TODO: deal with this
                }
                return http;
            }
            return bean;
        }
    }
}