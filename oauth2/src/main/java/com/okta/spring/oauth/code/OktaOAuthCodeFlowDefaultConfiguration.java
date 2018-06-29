/*
 * Copyright 2018 Okta, Inc.
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
package com.okta.spring.oauth.code;


import com.okta.spring.oauth.IssuerCondition;
import com.okta.spring.oauth.OktaTokenServicesConfig;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2SsoDefaultConfiguration;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @since 0.6.0
 */
@Configuration
@AutoConfigureBefore(OAuth2SsoDefaultConfiguration.class)
@ConditionalOnBean(OAuth2SsoDefaultConfiguration.class)
@Import({OktaOAuthCodeFlowConfiguration.class, OktaTokenServicesConfig.class})
@Conditional(IssuerCondition.class)
public class OktaOAuthCodeFlowDefaultConfiguration {}
