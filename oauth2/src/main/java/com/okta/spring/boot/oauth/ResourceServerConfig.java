/*
 * Copyright 2022-Present Okta, Inc.
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
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
class ResourceServerConfig {

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> converter) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtAuthenticationConverter;
    }

    @Bean
    Converter<Jwt, Collection<GrantedAuthority>> jwtConverter(OktaOAuth2Properties oktaOAuth2Properties, Collection<AuthoritiesProvider> authoritiesProviders) {

        Collection<Converter<Jwt, Collection<GrantedAuthority>>> converters = new ArrayList<>();
        converters.add(new JwtGrantedAuthoritiesConverter());
        converters.add(new OktaJwtGrantedAuthorityConverter(oktaOAuth2Properties.getGroupsClaim()));
        authoritiesProviders.stream()
            .map(provider -> (Converter<Jwt, Collection<GrantedAuthority>>) provider::getAuthorities)
            .forEach(converters::add);

        return new DelegatingJwtGrantedAuthoritiesConverter(converters);
    }
}
