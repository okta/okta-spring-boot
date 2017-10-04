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
package com.okta.spring.example;

import com.okta.spring.config.OktaOAuth2Properties;
import com.okta.spring.oauth.OktaUserInfoTokenServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;

@SpringBootApplication
@EnableOAuth2Sso
public class HostedLoginCodeFlowExampleApplication {

    private final Logger logger = LoggerFactory.getLogger(HostedLoginCodeFlowExampleApplication.class);

    private final OktaOAuth2Properties oktaOAuth2Properties;

    public HostedLoginCodeFlowExampleApplication(OktaOAuth2Properties oktaOAuth2Properties) {
        this.oktaOAuth2Properties = oktaOAuth2Properties;
    }

    public static void main(String[] args) {
        SpringApplication.run(HostedLoginCodeFlowExampleApplication.class, args);
    }

    /**
     * Enable OAuth claim checking from @PreAuthorize annotation.
     *
     * @see com.okta.spring.example.controllers.WelcomeController
     */
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    protected static class GlobalSecurityConfiguration extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            return new OAuth2MethodSecurityExpressionHandler();
        }
    }

    /**
     * Create an ApplicationListener that listens for successful logins and simply just logs the principal name.
     * @return a new listener
     */
    @Bean
    protected ApplicationListener<AuthenticationSuccessEvent> authenticationSuccessEventApplicationListener() {
        return event -> logger.info("Authentication Success with principal: {}", event.getAuthentication().getPrincipal());
    }

    @Bean
    protected Filter oktaSsoFilter(ApplicationEventPublisher applicationEventPublisher,
                                   OAuth2ClientContext oauth2ClientContext,
                                   PrincipalExtractor principalExtractor,
                                   AuthoritiesExtractor authoritiesExtractor,
                                   AuthorizationCodeResourceDetails authorizationCodeResourceDetails,
                                   ResourceServerProperties resourceServerProperties) {

        OAuth2ClientAuthenticationProcessingFilter oktaFilter = new OAuth2ClientAuthenticationProcessingFilter(oktaOAuth2Properties.getRedirectUri());
        oktaFilter.setApplicationEventPublisher(applicationEventPublisher);
        OAuth2RestTemplate oktaTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails, oauth2ClientContext);
        oktaFilter.setRestTemplate(oktaTemplate);
        UserInfoTokenServices tokenServices = new OktaUserInfoTokenServices(resourceServerProperties.getUserInfoUri(), authorizationCodeResourceDetails.getClientId(), oauth2ClientContext);
        tokenServices.setRestTemplate(oktaTemplate);
        tokenServices.setPrincipalExtractor(principalExtractor);
        tokenServices.setAuthoritiesExtractor(authoritiesExtractor);
        oktaFilter.setTokenServices(tokenServices);
        return oktaFilter;
    }

    @Configuration
    static class OAuth2SecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        private final Filter oktaSsoFilter;

        private final OktaOAuth2Properties oktaOAuth2Properties;

        OAuth2SecurityConfigurerAdapter(Filter oktaSsoFilter, OktaOAuth2Properties oktaOAuth2Properties) {
            this.oktaSsoFilter = oktaSsoFilter;
            this.oktaOAuth2Properties = oktaOAuth2Properties;
        }

        @Bean
        protected AuthenticationEntryPoint authenticationEntryPoint() {
            return new LoginUrlAuthenticationEntryPoint(oktaOAuth2Properties.getRedirectUri());
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .addFilterAfter(oktaSsoFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                    .authorizeRequests()
                        .antMatchers(HttpMethod.GET, oktaOAuth2Properties.getRedirectUri()).authenticated();
        }
    }
}
