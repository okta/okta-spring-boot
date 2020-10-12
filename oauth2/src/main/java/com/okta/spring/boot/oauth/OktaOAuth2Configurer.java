/*
 * Copyright 2018-Present Okta, Inc.
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
package com.okta.spring.boot.oauth;

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import com.okta.spring.boot.oauth.http.UserAgentRequestInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;

import static org.springframework.util.StringUtils.isEmpty;

final class OktaOAuth2Configurer extends AbstractHttpConfigurer<OktaOAuth2Configurer, HttpSecurity> {

    private static final Logger log = LoggerFactory.getLogger(OktaOAuth2Configurer.class);

    @SuppressWarnings("rawtypes")
    @Override
    public void init(HttpSecurity http) throws Exception {

        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // make sure OktaOAuth2Properties are available
        if (!context.getBeansOfType(OktaOAuth2Properties.class).isEmpty()) {
            OktaOAuth2Properties oktaOAuth2Properties = context.getBean(OktaOAuth2Properties.class);

            // if OAuth2ClientProperties bean is not available do NOT configure
            if (!context.getBeansOfType(OAuth2ClientProperties.class).isEmpty()
                && !isEmpty(oktaOAuth2Properties.getIssuer())
                && !isEmpty(oktaOAuth2Properties.getClientId())) {
                // configure Okta user services
                configureLogin(http, oktaOAuth2Properties);

                // check for RP-Initiated logout
                if (!context.getBeansOfType(OidcClientInitiatedLogoutSuccessHandler.class).isEmpty()) {
                    http.logout().logoutSuccessHandler(context.getBean(OidcClientInitiatedLogoutSuccessHandler.class));
                }

                // if issuer is root org, use opaque token validation
                if (TokenUtil.isRootOrgIssuer(oktaOAuth2Properties.getIssuer())) {
                    log.debug("Opaque Token validation/introspection will be configured.");
                    configureResourceServerForOpaqueTokenValidation(http);
                    return;
                }

                OAuth2ResourceServerConfigurer oAuth2ResourceServerConfigurer =
                    http.getConfigurer(OAuth2ResourceServerConfigurer.class);

                if (oAuth2ResourceServerConfigurer != null) {

                    // code below is wrapped in AccessController to address findbugs error 'DP_DO_INSIDE_DO_PRIVILEGED'
                    Field jwtConfigurerField = (Field) AccessController.doPrivileged((PrivilegedAction) () -> {
                        Field result = null;
                        try {
                            result = OAuth2ResourceServerConfigurer.class.getDeclaredField("jwtConfigurer");
                            result.setAccessible(true);
                        } catch (NoSuchFieldException e) {
                            log.warn("Could not get field 'jwtConfigurer' of {} via reflection",
                                OAuth2ResourceServerConfigurer.class.getName(), e);
                        }
                        return result;
                    });

                    if (jwtConfigurerField != null) {
                        OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurerValue =
                            (OAuth2ResourceServerConfigurer.JwtConfigurer) jwtConfigurerField.get(oAuth2ResourceServerConfigurer);

                        if (jwtConfigurerValue != null) {
                            log.debug("JWT configurer is set in OAuth resource server configuration. " +
                                "JWT validation will be configured.");
                            http.oauth2ResourceServer()
                                .jwt().jwtAuthenticationConverter(new OktaJwtAuthenticationConverter(oktaOAuth2Properties.getGroupsClaim()));
                        } else {
                            log.debug("JWT configurer is NOT set in OAuth resource server configuration. " +
                                "Opaque Token validation/introspection will be configured.");
                            configureResourceServerForOpaqueTokenValidation(http);
                        }
                    } else {
                        String errMsg = "JWT configurer field was not found in OAuth resource server configuration. " +
                            "Version incompatibility with Spring Security detected." +
                            "Check https://github.com/okta/okta-spring-boot for project updates.";
                        throw new IllegalStateException(errMsg);
                    }
                }
            }
        }
    }

    private void configureLogin(HttpSecurity http, OktaOAuth2Properties oktaOAuth2Properties) throws Exception {

        http.oauth2Login()
                .tokenEndpoint()
                    .accessTokenResponseClient(accessTokenResponseClient());

        if (oktaOAuth2Properties.getRedirectUri() != null) {
            http.oauth2Login().redirectionEndpoint().baseUri(oktaOAuth2Properties.getRedirectUri());
        }
    }

    private void configureResourceServerForOpaqueTokenValidation(HttpSecurity http) throws Exception {

        http.oauth2ResourceServer().opaqueToken();
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {

        RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(),
                                                                   new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.getInterceptors().add(new UserAgentRequestInterceptor());

        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRestOperations(restTemplate);

        return accessTokenResponseClient;
    }
}