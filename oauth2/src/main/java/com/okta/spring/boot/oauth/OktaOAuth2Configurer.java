package com.okta.spring.boot.oauth;

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

final class OktaOAuth2Configurer extends AbstractHttpConfigurer<OktaOAuth2Configurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {

        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // make sure OktaOAuth2Properties are available
        if (!context.getBeansOfType(OktaOAuth2Properties.class).isEmpty()) {
            OktaOAuth2Properties oktaOAuth2Properties = context.getBean(OktaOAuth2Properties.class);

            // if OAuth2ClientProperties bean is not available do NOT configure
            if (!context.getBeansOfType(OAuth2ClientProperties.class).isEmpty()) {
                // configure Okta user services
                configureLogin(http, oktaOAuth2Properties);
            }

            if (!context.getBeansOfType(OAuth2ResourceServerProperties.class).isEmpty()) {
                // configure Okta specific auth converter (extracts authorities from `groupsClaim`
                configureResourceServer(http, oktaOAuth2Properties);
            }
        }
    }

    private void configureLogin(HttpSecurity http, OktaOAuth2Properties oktaOAuth2Properties) throws Exception {
        http.oauth2Login()
                    .userInfoEndpoint()
                    .userService(new OktaOAuth2UserService(oktaOAuth2Properties.getGroupsClaim()))
                    .oidcUserService(new OktaOidcUserService(oktaOAuth2Properties.getGroupsClaim()));

        if (oktaOAuth2Properties.getRedirectUri() != null) {
            http.oauth2Login().redirectionEndpoint().baseUri(oktaOAuth2Properties.getRedirectUri());
        }
    }

    private void configureResourceServer(HttpSecurity http, OktaOAuth2Properties oktaOAuth2Properties) throws Exception {
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(new OktaJwtAuthenticationConverter(oktaOAuth2Properties.getGroupsClaim()));
    }
}
