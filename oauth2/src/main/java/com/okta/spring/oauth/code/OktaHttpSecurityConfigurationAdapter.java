package com.okta.spring.oauth.code;

import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

public class OktaHttpSecurityConfigurationAdapter implements SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity> {

    @Override
    public void init(HttpSecurity builder) throws Exception {}

    @Override
    public void configure(HttpSecurity builder) throws Exception {}
}
