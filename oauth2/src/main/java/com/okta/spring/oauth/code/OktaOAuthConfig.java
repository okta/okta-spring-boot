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

import com.okta.spring.config.OktaClientProperties;
import com.okta.spring.config.OktaOAuth2Properties;
import com.okta.spring.config.OktaPropertiesConfiguration;
import com.okta.spring.oauth.discovery.OidcDiscoveryConfiguration;
import com.okta.spring.oauth.discovery.OidcDiscoveryMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.Filter;
import java.util.function.Consumer;

@Configuration
@Import({OktaPropertiesConfiguration.class, OidcDiscoveryConfiguration.class})
@ConditionalOnClass({OAuth2ClientConfiguration.class})
@ConditionalOnBean(OAuth2ClientConfiguration.class)
public class OktaOAuthConfig {

    @Autowired
    private OktaOAuth2Properties oktaOAuth2Properties;

    @Autowired
    private OktaClientProperties oktaClientProperties;

    @Autowired
    private OidcDiscoveryMetadata discoveryMetadata;

    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private PrincipalExtractor principalExtractor;

    @Autowired
    private AuthoritiesExtractor authoritiesExtractor;

    @Autowired
    @Qualifier("oktaAuthorizationCodeResourceDetails")
    private AuthorizationCodeResourceDetails authorizationCodeResourceDetails;

    @Autowired
    @Qualifier("oktaResourceServerProperties")
    private ResourceServerProperties resourceServerProperties;

    @PostConstruct
    protected void init() {

        // update properties based on discovery if needed

        updateIfNotSet(oktaOAuth2Properties::setIssuer,
                       oktaOAuth2Properties.getIssuer(),
                       discoveryMetadata.getIssuer());

        Assert.hasText(oktaOAuth2Properties.getIssuer(), "Unset OAuth2 Issuer, set property `okta.oauth2.issuer`.");
        String issuer = oktaOAuth2Properties.getIssuer();
        String baseUrl = issuer.substring(0, issuer.lastIndexOf("/oauth2/"));

        updateIfNotSet(oktaClientProperties::setOrgUrl,
                       oktaClientProperties.getOrgUrl(),
                       baseUrl);

        // force using the same clientID
        // TODO: this is for debugging, there is something odd going on here
        if (StringUtils.hasText(oktaOAuth2Properties.getClientId())) {
            authorizationCodeResourceDetails.setClientId(oktaOAuth2Properties.getClientId());
        }
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

    @Bean
    @ConditionalOnMissingBean
    PrincipalExtractor principalExtractor() {
        return new ClaimsPrincipalExtractor(oktaOAuth2Properties.getPrincipalClaim());
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthoritiesExtractor authoritiesExtractor() {
        return new ClaimsAuthoritiesExtractor(oktaOAuth2Properties.getRolesClaim());
    }

    @Bean
    @ConditionalOnMissingBean
    public WebSecurityConfigurerAdapter oktaWebSecurityConfigurerAdapter() {
        return new OktaWebSecurityConfigurerAdapter();
    }

    @Bean
    @ConditionalOnMissingBean(name = "oktaAuthorizationCodeResourceDetails")
    @ConfigurationProperties("security.oauth2.client")
    protected AuthorizationCodeResourceDetails oktaAuthorizationCodeResourceDetails(OidcDiscoveryMetadata discoveryMetadata, OktaOAuth2Properties oktaOAuth2Properties) {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        details.setScope(oktaOAuth2Properties.getScopes());

        details.setClientId(oktaOAuth2Properties.getClientId());
        details.setClientSecret(oktaOAuth2Properties.getClientSecret());
        details.setAccessTokenUri(discoveryMetadata.getTokenEndpoint());
        details.setUserAuthorizationUri(discoveryMetadata.getAuthorizationEndpoint());

        return details;
    }

    @Bean
    @ConditionalOnMissingBean(name = "oktaResourceServerProperties")
    @ConfigurationProperties("security.oauth2.resource")
    protected ResourceServerProperties oktaResourceServerProperties(OidcDiscoveryMetadata discoveryMetadata) {
        ResourceServerProperties props = new ResourceServerProperties();
        props.setPreferTokenInfo(false);

        props.setUserInfoUri(discoveryMetadata.getUserinfoEndpoint());
        props.setTokenInfoUri(discoveryMetadata.getIntrospectionEndpoint());

        return props;
    }

    @Bean
    @ConditionalOnMissingBean
    protected OktaHttpSecurityConfigurationAdapter defaultOktaHttpSecurityConfigurationAdapter() {
        return new DefaultOktaSecurityConfigurer(ssoFilter(), oktaOAuth2Properties.getRedirectUri());
    }

    private Filter ssoFilter() {

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
}