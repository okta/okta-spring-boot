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

import com.okta.spring.oauth.OktaProperties;
import com.okta.spring.oauth.discovery.DiscoveryMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import javax.servlet.Filter;
import java.util.function.Consumer;

@Configuration
@Import(OktaOAuthConfig.OktaPropertiesConfiguration.class)
@ConditionalOnClass({OAuth2ClientConfiguration.class})
@ConditionalOnBean(OAuth2ClientConfiguration.class)
@EnableConfigurationProperties(OktaProperties.class)
public class OktaOAuthConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private OktaProperties oktaProperties;

    @Autowired
    private PrincipalExtractor principalExtractor;

    @Autowired
    private AuthoritiesExtractor authoritiesExtractor;

    @Autowired
    private DiscoveryMetadata discoveryMetadata;

    @Autowired
    @Qualifier("oktaAuthorizationCodeResourceDetails")
    private AuthorizationCodeResourceDetails authorizationCodeResourceDetails;

    @Autowired
    @Qualifier("oktaResourceServerProperties")
    private ResourceServerProperties resourceServerProperties;


    @PostConstruct
    protected void init() {

        // update properties based on discovery if needed

        updateIfNotSet(oktaProperties.getOauth2()::setIssuer,
                       oktaProperties.getOauth2().getIssuer(),
                       discoveryMetadata.getIssuer());

        String issuer = oktaProperties.getOauth2().getIssuer();
        String baseUrl = issuer.substring(0, issuer.lastIndexOf("/oauth2/"));

        updateIfNotSet(oktaProperties.getClient()::setOrgUrl,
                       oktaProperties.getClient().getOrgUrl(),
                       baseUrl);
    }

    /**
     * If {code}currentValue{code} is empty, then {code}newValue{code} is applied to {code}setter{code}.
     * @param setter method to call to update value if needed
     * @param currentValue the current value to be checked if not empty
     * @param newValue new value to use if the consumer needs to be called
     */
    private void updateIfNotSet(Consumer<String> setter, String currentValue, String newValue) {
        if (!StringUtils.hasText(currentValue)) {
            setter.accept(newValue);
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // FIXME: MVC bleed
        http.authorizeRequests().antMatchers("/okta/*.css").permitAll();

        // add the SSO Filter
        http.addFilterBefore(ssoFilter(), UsernamePasswordAuthenticationFilter.class);

        // configure the local login page if we have one, otherwise redirect
        String loginPage = oktaProperties.getOauth2().getCustomLoginRoute();
        if (!StringUtils.hasText(loginPage)) {
            loginPage = oktaProperties.getOauth2().getRedirectUri();
        }
        http.authorizeRequests().antMatchers(loginPage).permitAll();
        http.formLogin().loginPage(oktaProperties.getOauth2().getRedirectUri());

        // require full auth for all other resources
        http.authorizeRequests().anyRequest().fullyAuthenticated();
    }

    private Filter ssoFilter() {

        OAuth2ClientAuthenticationProcessingFilter oktaFilter = new OAuth2ClientAuthenticationProcessingFilter(oktaProperties.getOauth2().getRedirectUri());
        OAuth2RestTemplate oktaTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails, oauth2ClientContext);
        oktaFilter.setRestTemplate(oktaTemplate);
        UserInfoTokenServices tokenServices = new OktaUserInfoTokenServices(resourceServerProperties.getUserInfoUri(), authorizationCodeResourceDetails.getClientId(), oauth2ClientContext);
        tokenServices.setRestTemplate(oktaTemplate);
        tokenServices.setPrincipalExtractor(principalExtractor);
        tokenServices.setAuthoritiesExtractor(authoritiesExtractor);
        oktaFilter.setTokenServices(tokenServices);
        return oktaFilter;
    }

    @Bean
    PrincipalExtractor principalExtractor() {
        return new ClaimsPrincipalExtractor(oktaProperties.getOauth2().getPrincipalClaim());
    }

    @Bean
    public AuthoritiesExtractor authoritiesExtractor() {
        return new ClaimsAuthoritiesExtractor(oktaProperties.getOauth2().getRolesClaim());
    }

    /**
     * General configuration will take precedence over any discovery properties.
     */
    @Configuration
    static class OktaPropertiesConfiguration {

        @Autowired
        private OktaProperties oktaProperties;

        @Autowired
        private RestTemplate restTemplate;

        @Bean
        @ConfigurationProperties("security.oauth2.client")
        protected AuthorizationCodeResourceDetails oktaAuthorizationCodeResourceDetails(DiscoveryMetadata discoveryMetadata) {
            AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
            details.setClientAuthenticationScheme(AuthenticationScheme.form);
            details.setScope(oktaProperties.getOauth2().getScopes());

            details.setClientId(oktaProperties.getOauth2().getClientId());
            details.setClientSecret(oktaProperties.getOauth2().getClientSecret());
            details.setAccessTokenUri(discoveryMetadata.getTokenEndpoint());
            details.setUserAuthorizationUri(discoveryMetadata.getAuthorizationEndpoint());

            return details;
        }

        @Bean
        @ConfigurationProperties("security.oauth2.resource")
        protected ResourceServerProperties oktaResourceServerProperties(DiscoveryMetadata discoveryMetadata) {
            ResourceServerProperties props = new ResourceServerProperties();
            props.setPreferTokenInfo(false);

            props.setUserInfoUri(discoveryMetadata.getUserinfoEndpoint());
            props.setTokenInfoUri(discoveryMetadata.getIntrospectionEndpoint());

            return props;
        }

        @Bean
        protected DiscoveryMetadata discoveryMetadata() {

            String discoveryUrl = oktaProperties.getOauth2().getDiscoveryUri();

            if (!StringUtils.hasText(discoveryUrl)) {
                discoveryUrl = oktaProperties.getOauth2().getIssuer() + "/.well-known/openid-configuration";
            }

            if (!StringUtils.hasText(discoveryUrl)) {
                Assert.hasText(discoveryUrl, "Unknown OIDC discovery endpoint, set property `okta.discoveryUrl` or `okta.issuer`.");
            }

            return restTemplate.getForObject(discoveryUrl, DiscoveryMetadata.class);
        }

        @Bean
        public RestTemplate restTemplate(RestTemplateBuilder builder) {
            return builder.build();
        }
    }
}