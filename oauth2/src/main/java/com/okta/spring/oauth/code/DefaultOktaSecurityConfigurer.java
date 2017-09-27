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