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
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Configuration
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnClass(JwtAuthenticationToken.class)
@ConditionalOnOktaResourceServerProperties
@EnableConfigurationProperties(OktaOAuth2Properties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
class OktaOAuth2ResourceServerAutoConfig {

    @Bean
    @ConditionalOnMissingBean
    JwtDecoder jwtDecoder(OAuth2ResourceServerProperties oAuth2ResourceServerProperties,
                          OktaOAuth2Properties oktaOAuth2Properties) {

            NimbusJwtDecoderJwkSupport decoder = new NimbusJwtDecoderJwkSupport(oAuth2ResourceServerProperties.getJwt().getJwkSetUri());
            decoder.setJwtValidator(TokenUtil.jwtValidator(oAuth2ResourceServerProperties.getJwt().getIssuerUri(), oktaOAuth2Properties.getAudience()));
            decoder.setRestOperations(restOperations());
            return decoder;
    }

    private RestOperations restOperations() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());
        return restTemplate;
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