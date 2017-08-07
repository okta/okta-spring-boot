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
package com.okta.spring.oauth;

import org.springframework.beans.InvalidPropertyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.IssuerClaimVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URL;

@EnableConfigurationProperties(OauthProperties.class)
@EnableResourceServer
@EnableWebSecurity
@Configuration
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private OauthProperties oauthProperties;

    @Override
    public void configure(final ResourceServerSecurityConfigurer config) {
        config.resourceId(oauthProperties.getAudience()); // set audience
        config.tokenServices(tokenServices());
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceServerTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenStore tokenStore() {
        return new JwkTokenStore(issuerUrl() + "/v1/keys", accessTokenConverter(), jwtClaimsSetVerifier());
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setAccessTokenConverter(new ConfigurableAccessTokenConverter(oauthProperties.getScopeClaim(), oauthProperties.getRolesClaim()));
        return jwtAccessTokenConverter;
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtClaimsSetVerifier jwtClaimsSetVerifier() {
        try {
            return new IssuerClaimVerifier(new URL(issuerUrl()));
        } catch (MalformedURLException e) {
            throw new InvalidPropertyException(JwtClaimsSetVerifier.class, "okta.oauth2.issuer", "Failed to parse issuer URL", e);
        }
    }

    private String issuerUrl() {
        String issuerUrl = oauthProperties.getIssuer();
        Assert.hasText(issuerUrl, "Property 'okta.oauth.issuer' is required, must not be null or empty.");
        return issuerUrl;
    }

}
