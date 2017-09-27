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
package com.okta.spring.oauth.code

import com.okta.spring.config.DiscoveryMetadata
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client
import org.springframework.web.client.RestTemplate

import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

@Configuration
@EnableOAuth2Client
@EnableAutoConfiguration
class MockCodeFlowApp {

    @Bean
    RestTemplateBuilder restTemplateBuilder() {

        DiscoveryMetadata metadata = new DiscoveryMetadata()
        metadata.userinfoEndpoint = "https://okta.example.com/userinfoEndpoint"
        metadata.introspectionEndpoint = "https://okta.example.com/introspectionEndpoint"

        RestTemplate template = mock(RestTemplate)
        RestTemplateBuilder builder = mock(RestTemplateBuilder)
        when(builder.build()).thenReturn(template)
        when(template.getForObject("https://okta.example.com/oauth2/my_issuer/.well-known/openid-configuration", DiscoveryMetadata.class)).thenReturn(metadata)

        return builder

    }

}
