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
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@AutoConfigureBefore(ReactiveOAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnOktaResourceServerProperties
@EnableConfigurationProperties({OktaOAuth2Properties.class, OAuth2ResourceServerProperties.class})
@ConditionalOnClass({ EnableWebFluxSecurity.class, BearerTokenAuthenticationToken.class, ReactiveJwtDecoder.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
class ReactiveOktaOAuth2ResourceServerAutoConfig {

    @Bean
    @ConditionalOnMissingBean
    ReactiveJwtDecoder jwtDecoder(OAuth2ResourceServerProperties oAuth2ResourceServerProperties, OktaOAuth2Properties oktaOAuth2Properties) {

        NimbusReactiveJwtDecoder.JwkSetUriReactiveJwtDecoderBuilder builder =
            NimbusReactiveJwtDecoder.withJwkSetUri(oAuth2ResourceServerProperties.getJwt().getJwkSetUri());
        builder.webClient(webClient());
        NimbusReactiveJwtDecoder decoder = builder.build();
        decoder.setJwtValidator(TokenUtil.jwtValidator(oAuth2ResourceServerProperties.getJwt().getIssuerUri(), oktaOAuth2Properties.getAudience()));
        return decoder;
    }

    private WebClient webClient() {
        return WebClientUtil.createWebClient();
    }
}