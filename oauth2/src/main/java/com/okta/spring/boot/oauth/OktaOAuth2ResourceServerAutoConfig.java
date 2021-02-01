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

import com.okta.commons.lang.Strings;
import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import com.okta.spring.boot.oauth.http.UserAgentRequestInterceptor;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.client.RestTemplate;

import java.util.Collection;
import java.util.Collections;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Optional;

@Configuration
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnClass(JwtAuthenticationToken.class)
@ConditionalOnOktaResourceServerProperties
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
class OktaOAuth2ResourceServerAutoConfig {

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(OktaOAuth2Properties oktaOAuth2Properties) {
        OktaJwtAuthenticationConverter converter = new OktaJwtAuthenticationConverter(oktaOAuth2Properties.getGroupsClaim());
        converter.setJwtGrantedAuthoritiesConverter(new JwtGrantedAuthoritiesConverter());
        return converter;
    }

    @Bean
    @ConditionalOnMissingBean
    JwtDecoder jwtDecoder(OAuth2ResourceServerProperties oAuth2ResourceServerProperties,
                          OktaOAuth2Properties oktaOAuth2Properties) {

        NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(oAuth2ResourceServerProperties.getJwt().getJwkSetUri());
        builder.restOperations(restTemplate(oktaOAuth2Properties));
        NimbusJwtDecoder decoder = builder.build();
        decoder.setJwtValidator(TokenUtil.jwtValidator(oktaOAuth2Properties.getIssuer(), oktaOAuth2Properties.getAudience()));
        return decoder;
    }

    static RestTemplate restTemplate(OktaOAuth2Properties oktaOAuth2Properties) {

        Proxy proxy;

        OktaOAuth2Properties.Proxy proxyProperties = oktaOAuth2Properties.getProxy();
        Optional<BasicAuthenticationInterceptor> basicAuthenticationInterceptor = Optional.empty();
        if (proxyProperties != null && Strings.hasText(proxyProperties.getHost()) && proxyProperties.getPort() > 0) {
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyProperties.getHost(), proxyProperties.getPort()));

            if (Strings.hasText(proxyProperties.getUsername()) &&
                Strings.hasText(proxyProperties.getPassword())) {

                basicAuthenticationInterceptor = Optional.of(new BasicAuthenticationInterceptor(proxyProperties.getUsername(),
                    proxyProperties.getPassword()));
            }
        } else {
            proxy = Proxy.NO_PROXY;
        }

        RestTemplate restTemplate = new RestTemplate();
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());
        basicAuthenticationInterceptor.ifPresent(restTemplate.getInterceptors()::add);
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setProxy(proxy);
        restTemplate.setRequestFactory(requestFactory);
        return restTemplate;
    }

    @Bean
    @Conditional(OktaOpaqueTokenIntrospectConditional.class)
    OpaqueTokenIntrospector opaqueTokenIntrospector(OktaOAuth2Properties oktaOAuth2Properties,
                                                    OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {

        RestTemplate restTemplate = restTemplate(oktaOAuth2Properties);
        restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(
            oAuth2ResourceServerProperties.getOpaquetoken().getClientId(),
            oAuth2ResourceServerProperties.getOpaquetoken().getClientSecret()));

        OpaqueTokenIntrospector delegate = new NimbusOpaqueTokenIntrospector(
            oAuth2ResourceServerProperties.getOpaquetoken().getIntrospectionUri(),
            restTemplate);

        return token -> {
            OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);

            Collection<GrantedAuthority> mappedAuthorities =
                Collections.unmodifiableCollection(
                    TokenUtil.opaqueTokenClaimsToAuthorities(principal.getAttributes(), oktaOAuth2Properties.getGroupsClaim(), principal.getAuthorities()));

            return new DefaultOAuth2AuthenticatedPrincipal(
                principal.getName(), principal.getAttributes(), mappedAuthorities);
        };
    }
}