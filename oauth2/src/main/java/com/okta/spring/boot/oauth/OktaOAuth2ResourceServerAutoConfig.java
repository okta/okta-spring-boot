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
import com.okta.spring.boot.oauth.http.UserAgentRequestInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;

@Configuration
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnClass(JwtAuthenticationToken.class)
@ConditionalOnOktaResourceServerProperties
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
class OktaOAuth2ResourceServerAutoConfig {
    private static final Logger log = LoggerFactory.getLogger(OktaOAuth2ResourceServerAutoConfig.class);

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
        builder.restOperations(restTemplate());
        NimbusJwtDecoder decoder = builder.build();
        decoder.setJwtValidator(TokenUtil.jwtValidator(oktaOAuth2Properties.getIssuer(), oktaOAuth2Properties.getAudience()));
        return decoder;
    }

    private RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());
        return restTemplate;
    }

    @Bean
    @Conditional(OktaOpaqueTokenIntrospectConditional.class)
    OpaqueTokenIntrospector opaqueTokenIntrospector(OktaOAuth2Properties oktaOAuth2Properties,
                                                    OAuth2ResourceServerProperties oAuth2ResourceServerProperties) throws Exception {

        OpaqueTokenIntrospector delegate = new NimbusOpaqueTokenIntrospector(
            oAuth2ResourceServerProperties.getOpaquetoken().getIntrospectionUri(),
            oAuth2ResourceServerProperties.getOpaquetoken().getClientId(),
            oAuth2ResourceServerProperties.getOpaquetoken().getClientSecret());

        /* NimbusOpaqueTokenIntrospector constructor does not presently allow instantiation
           with client-id, client-secret & restOperations combination.
           We will now add 'UserAgentRequestInterceptor` header to the `restOperations`
           put in by NimbusOpaqueTokenIntrospector.
        */
        Field restOperationsField = (Field) AccessController.doPrivileged((PrivilegedAction) () -> {
            Field result = null;
            try {
                result = NimbusOpaqueTokenIntrospector.class.getDeclaredField("restOperations");
                result.setAccessible(true);
            } catch (NoSuchFieldException e) {
                log.warn("Could not get field 'restOperations' of {} via reflection",
                    NimbusOpaqueTokenIntrospector.class.getName(), e);
            }
            return result;
        });

        String errMsg = "restOperations field was not found in NimbusOpaqueTokenIntrospector class. " +
            "Version incompatibility with Spring Security detected." +
            "Check https://github.com/okta/okta-spring-boot for project updates.";
        Assert.notNull(restOperationsField, errMsg);

        RestTemplate restTemplate = (RestTemplate) restOperationsField.get(delegate);
        Assert.notNull(restTemplate, errMsg);
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());

        restOperationsField.set(delegate, restTemplate);

        return token -> {
            OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
            Collection<GrantedAuthority> mappedAuthorities =
                (Collection<GrantedAuthority>) TokenUtil.tokenClaimsToAuthorities(principal.getAttributes(), oktaOAuth2Properties.getGroupsClaim());
            return new DefaultOAuth2AuthenticatedPrincipal(
                principal.getName(), principal.getAttributes(), mappedAuthorities);
        };
    }
}