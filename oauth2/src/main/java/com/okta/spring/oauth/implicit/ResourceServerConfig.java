/*
 * Copyright 2017 Okta, Inc.
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
package com.okta.spring.oauth.implicit;

import com.okta.spring.config.OktaOAuth2Properties;
import com.okta.spring.oauth.OktaTokenServicesConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
/**
 * Configuration for OAuth2 Implicit flow.
 * @since 0.1.0
 */
@ConditionalOnBean(ResourceServerConfiguration.class)
@Configuration
@Import(OktaTokenServicesConfig.class)
public class ResourceServerConfig {

    private final OktaOAuth2Properties oktaOAuth2Properties;

    public ResourceServerConfig(OktaOAuth2Properties oktaOAuth2Properties) {
        this.oktaOAuth2Properties = oktaOAuth2Properties;
    }

    @Bean
    @Primary
    @ConditionalOnBean(ResourceServerTokenServices.class)
    public ResourceServerConfigurerAdapter resourceServerConfigurerAdapter(ResourceServerTokenServices tokenServices) {
        return new ResourceServerConfigurerAdapter() {
            @Override
            public void configure(final ResourceServerSecurityConfigurer config) {
                config.resourceId(oktaOAuth2Properties.getAudience()); // set resourceId to the audience
                config.tokenServices(tokenServices);
            }
        };
    }
}