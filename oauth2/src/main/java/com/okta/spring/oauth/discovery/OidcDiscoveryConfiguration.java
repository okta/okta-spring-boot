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
package com.okta.spring.oauth.discovery;

import com.okta.spring.config.OktaOAuth2Properties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;

@Configuration
public class OidcDiscoveryConfiguration {

    @Bean
    @ConditionalOnMissingBean
    protected OidcDiscoveryMetadata oktaOidcDiscoveryMetadata(OktaOAuth2Properties oktaOAuth2Properties) {
        Assert.hasText(oktaOAuth2Properties.getIssuer(), "issuer cannot be empty, this is typically cased a missing property: 'okta.oauth2.issuer'");
        return new OidcDiscoveryClient(oktaOAuth2Properties.getIssuer()).discover();
    }
}
