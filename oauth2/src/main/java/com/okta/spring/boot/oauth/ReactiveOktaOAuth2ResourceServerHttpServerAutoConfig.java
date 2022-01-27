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
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;

import java.util.Collection;

@Configuration
@ConditionalOnOktaResourceServerProperties
@AutoConfigureAfter(ReactiveOktaOAuth2ResourceServerAutoConfig.class)
@EnableConfigurationProperties({OktaOAuth2Properties.class, OAuth2ResourceServerProperties.class})
@Import(ResourceServerConfig.class)
@ConditionalOnClass({ EnableWebFluxSecurity.class, BearerTokenAuthenticationToken.class, ReactiveJwtDecoder.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
class ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig {

    @Bean
    BeanPostProcessor oktaOAuth2ResourceServerBeanPostProcessor(Converter<Jwt, Collection<GrantedAuthority>> converter) {
        return new OktaOAuth2ResourceServerBeanPostProcessor(converter);
    }

    static class OktaOAuth2ResourceServerBeanPostProcessor implements BeanPostProcessor {

        private final Converter<Jwt, Collection<GrantedAuthority>> converter;

        OktaOAuth2ResourceServerBeanPostProcessor(Converter<Jwt, Collection<GrantedAuthority>> converter) {
            this.converter = converter;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (bean instanceof ServerHttpSecurity) {
                final ServerHttpSecurity http = (ServerHttpSecurity) bean;
                http.oauth2ResourceServer().jwt()
                        .jwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(
                            jwt -> new JwtAuthenticationToken(jwt, converter.convert(jwt))
                        ));
            }
            return bean;
        }
    }
}