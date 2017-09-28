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
package com.okta.spring.oauth.code;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.Filter;

@Order(100)
public class DefaultOktaSecurityConfigurer extends OktaHttpSecurityConfigurationAdapter {

    private final Filter ssoFilter;

    private final String redirectUri;

    public DefaultOktaSecurityConfigurer(Filter ssoFilter, String redirectUri) {
        this.ssoFilter = ssoFilter;
        this.redirectUri = redirectUri;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

        // add the SSO Filter
        http.addFilterBefore(ssoFilter, UsernamePasswordAuthenticationFilter.class);

//        http.authorizeRequests().antMatchers(oktaOAuth2Properties.getRedirectUri()).permitAll();
        http.formLogin().loginPage(redirectUri);

        // require full auth for all other resources
        http.authorizeRequests().anyRequest().fullyAuthenticated();
    }
}